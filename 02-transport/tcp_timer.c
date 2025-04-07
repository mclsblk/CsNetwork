#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	pthread_mutex_t timer_list_lock;
	pthread_mutex_init(&timer_list_lock, NULL);
	pthread_mutex_lock(&timer_list_lock);

	struct tcp_sock *tsk, *q;
	list_for_each_entry_safe(tsk, q, &timer_list, timewait.list){
		if(tsk->timewait.enable){
			tsk->timewait.timeout -= TCP_TIMER_SCAN_INTERVAL;
			if(tsk->timewait.timeout <= 0){
				tcp_set_state(tsk, TCP_CLOSED);
				struct list_head *list = &tsk->timewait.list;
				list_delete_entry(list);
				log(DEBUG, "entry deleted from timer_list");
				if(tcp_unhash) tcp_unhash(tsk);
				if(tcp_bind_unhash) tcp_bind_unhash(tsk);
				if(tsk) free_tcp_sock(tsk);
				log(DEBUG, "tcp sock %p is released", tsk);
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
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
