#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"
#include "log.h"

// Define the maximum number of retries for retransmission
#define TCP_MAX_RETRIES 5

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	pthread_mutex_t timer_list_lock;
	pthread_mutex_init(&timer_list_lock, NULL);
	pthread_mutex_lock(&timer_list_lock);


	struct tcp_sock *tk, *q;
	list_for_each_entry_safe(tk, q, &timer_list, timewait.list){

		// 先获取socket锁，防止并发修改
		if (pthread_mutex_trylock(&tk->sk_lock) != 0) {
			// 如果无法获取锁，跳过这个socket
			continue;
		}

		if(tk->timewait.enable){
			tk->timewait.timeout -= TCP_TIMER_SCAN_INTERVAL;
			if(tk->timewait.timeout <= 0){
				if(tk->timewait.type == 0){
					tcp_set_state(tk, TCP_CLOSED);
					struct list_head *list = &tk->timewait.list;
					list_delete_entry(list);
					log(DEBUG, "entry deleted from timer_list");
					if(tcp_unhash) tcp_unhash(tk);
					if(tcp_bind_unhash) tcp_bind_unhash(tk);
					if(tk) free_tcp_sock(tk);
					log(DEBUG, "tcp sock %p is released", tk);	
					continue;
				}
				else if(tk->timewait.type == 2){
					if(tk->snd_wnd < TCP_MSS && tk->state != TCP_CLOSED){
						tcp_send_probe_packet(tk);
						tk->timewait.timeout = TCP_RETRANS_INTERVAL_INITIAL;
						log(DEBUG, "tcp sock %p is in persist state", tk);
					}
					else{
						tcp_unset_persist_timer(tk);
						struct list_head *list = &tk->timewait.list;
						list_delete_entry(list);
						log(DEBUG, "persist_timer deleted from timer_list");
					}
				}
				else{
					log(ERROR, "tcp sock %p has an invalid timer type", tk);
				}
			}
		}
		if(tk->retrans_timer.enable){
			// 重传计时器处理
			tk->retrans_timer.timeout -= TCP_TIMER_SCAN_INTERVAL;
			if(tk->retrans_timer.timeout <= 0){
				if(tk->state != TCP_CLOSED){
					// 检查重传次数是否达到上限
					if(tk->timewait.retries >= TCP_MAX_RETRIES){
						// 达到重传上限，强制关闭连接
						log(ERROR, "tcp sock %p max retries reached, closing connection", tk);
						tcp_send_reset(tk);
						tcp_set_state(tk, TCP_CLOSED);
						
						// 从各种队列中移除
						if(tcp_unhash) tcp_unhash(tk);
						if(tcp_bind_unhash) tcp_bind_unhash(tk);
						
						// 删除定时器
						struct list_head *list = &tk->timewait.list;
						list_delete_entry(list);
						tk->timewait.enable = 0;
						
						// 唤醒所有等待的进程
						wake_up(tk->wait_connect);
						wake_up(tk->wait_accept);
						wake_up(tk->wait_recv);
						wake_up(tk->wait_send);
						
						// 释放socket
						if(tk) free_tcp_sock(tk);
						continue;
						log(DEBUG, "tcp sock %p is released after max retries", tk);
					}
					else{
						// 重新设置超时时间
						tk->timewait.timeout = TCP_RETRANS_INTERVAL_INITIAL;
						tk->timewait.retries++;
						tcp_retrans_send_buffer(tk);
						log(DEBUG, "tcp sock %p retransmission, retry count: %d", tk, tk->timewait.retries);
					}
				}
			}
			
		}
		if(timer_list.next == &timer_list){
			log(DEBUG, "timer_list is empty");
		}
	}

	pthread_mutex_unlock(&timer_list_lock);
	pthread_mutex_destroy(&timer_list_lock);

}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	if(tsk->state != TCP_FIN_WAIT_2){
		log(ERROR, "tcp_set_timewait_timer: tcp sock is not in FIN_WAIT_2");
		return;
	}

	tcp_set_state(tsk, TCP_TIME_WAIT);
	tsk->timewait.type = 0;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	tsk->timewait.enable = 1;
	list_add_tail(&tsk->timewait.list, &timer_list);

	log(DEBUG, "tcp_set_timewait_timer: tcp sock %p is set to timewait", tsk);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg){
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}

/*
1. 如果已经启用，则直接退出
2. 创建定时器，设置各个成员变量，设置timeout为比如TCP_RETRANS_INTERVAL_INITIAL
3. 增加tsk的引用计数，将定时器加入timer_list末尾
*/
void tcp_set_persist_timer(struct tcp_sock *tsk){
	if(tsk->timewait.enable == 1){
		return;
	}

	tsk->ref_cnt += 1;
	tsk->timewait.type = 2;
	tsk->timewait.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->timewait.enable = 1;
	list_add_tail(&tsk->timewait.list, &timer_list);

	log(DEBUG, "tcp_set_persist_timer: tcp sock %p is set to timewait", tsk);
}

/*
1. 如果已经禁用，不做任何事
2. 调用free_tcp_sock减少tsk引用计数，并从链表中移除timer
*/
void tcp_unset_persist_timer(struct tcp_sock *tsk){
	if(tsk->timewait.enable == 0){
		log(ERROR, "tcp_set_persist_timer: tcp sock is already disabled");
		return;
	}

	tsk->timewait.enable = 0;
	list_delete_entry(&tsk->timewait.list);
	free_tcp_sock(tsk);

	log(DEBUG, "tcp_unset_persist_timer: tcp sock %p is unset", tsk);
}

/*
1. 如果已经启用，则更新超时时间为当前的RTO后退出
2. 创建定时器，设置各个成员变量，初始RTO为TCP_RETRANS_INTERVAL_INITIAL。
3. 增加tsk的引用计数，将定时器加入timer_list末尾
*/
void tcp_set_retrans_timer(struct tcp_sock *tsk){

	if(tsk->retrans_timer.enable == 1){
        log(DEBUG, "tcp_set_retrans_timer: tcp sock timer already enabled, updating timeout");
        tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
        tsk->retrans_timer.retries = 0;  // 重置重传次数
        return;
    }

	tsk->ref_cnt += 1;
	tsk->retrans_timer.type = 1;
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->retrans_timer.enable = 1;
	tsk->retrans_timer.retries = 0; // 初始化重传计数为0
	list_add_tail(&tsk->timewait.list, &timer_list);

	//log(DEBUG, "tcp_set_retrans_timer: tcp sock %p is set to retrans", tsk);
}

/*
1. 如果已经禁用，不做任何事
2. 调用free_tcp_sock减少tsk引用计数，并从链表中移除timer
*/
void tcp_unset_retrans_timer(struct tcp_sock *tsk){
	if(tsk->retrans_timer.enable == 0){
		log(ERROR, "tcp_set_retrans_timer: tcp sock is already disabled");
		return;
	}

	tsk->retrans_timer.enable = 0;
	list_delete_entry(&tsk->timewait.list);
	free_tcp_sock(tsk);

	//log(DEBUG, "tcp_unset_retrans_timer: tcp sock %p is unset", tsk);
}

/*
1. 确认定时器是启用状态
2. 如果发送队列为空，则删除定时器，并且唤醒发送数据的进程。否则重置计时器，包括timeout和重传计数。

注意调用这个函数之前，需要完成对发送队列的更新。
*/
void tcp_update_retrans_timer(struct tcp_sock *tsk){

	pthread_mutex_t timer_list_lock;
	pthread_mutex_init(&timer_list_lock, NULL);
	pthread_mutex_lock(&timer_list_lock);

	if(tsk->retrans_timer.enable == 0){
		log(ERROR, "tcp_update_retrans_timer: tcp sock is not enabled");
		return;
	}

	if(list_empty(&tsk->send_buf)){
		log(DEBUG,"transmission continue");
		wake_up(tsk->wait_send);
		tcp_unset_retrans_timer(tsk);		
	}
	else{
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
		tsk->retrans_timer.retries = 0; // 重传计数归零
		log(DEBUG, "tcp_update_retrans_timer: tcp sock %p is updated", tsk);
	}

	pthread_mutex_unlock(&timer_list_lock);
	pthread_mutex_destroy(&timer_list_lock);
}