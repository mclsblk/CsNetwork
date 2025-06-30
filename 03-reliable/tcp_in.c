#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	//log(DEBUG, "a");
	if(cb->pl_len > 0) tsk->rcv_nxt = cb->seq + cb->pl_len;  // 设置期望收到的下一个序列号
	else if(cb->flags & TCP_FIN || cb->flags & TCP_SYN) tsk->rcv_nxt = cb->seq + 1;  // 设置期望收到的下一个序列号
	//log(DEBUG, "b");
	tsk->snd_una = cb->ack;      // 确认已经收到的序列号
	tsk->adv_wnd = cb->rwnd; // 更新接收窗口
	tsk->snd_wnd = min(tsk->adv_wnd, tsk->cwnd); // 更新发送窗口
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	pthread_mutex_lock(&tsk->sk_lock);

	log(DEBUG, "rcv_nxt:%d, cb->seq:%d, cb->pl_len:%d", tsk->rcv_nxt, cb->seq, cb->pl_len);

	switch (tsk->state) {
	case TCP_CLOSED:
		log(ERROR, "TCP_CLOSED should not call tcp_process");
		break;

	case TCP_LISTEN:
		log(DEBUG, "received packet in TCP_LISTEN state");

		if(cb->flags == TCP_SYN || 
			cb->flags == (TCP_SYN | TCP_ACK)){
			struct tcp_sock *child = alloc_tcp_sock();
			child->sk_sip = cb->daddr;
			child->sk_sport = cb->dport;
			child->sk_dip = cb->saddr;
			child->sk_dport = cb->sport;
			child->parent = tsk;

			child->iss = tcp_new_iss();
			child->snd_nxt = child->iss;
        	child->snd_una = child->iss;
       		child->rcv_nxt = cb->seq + 1;
			child->snd_wnd = TCP_DEFAULT_WINDOW;

			init_list_head(&child->list);
			list_add_tail(&child->list, &tsk->listen_queue);


			tcp_set_state(child, TCP_SYN_RECV);
			log(DEBUG, "new child tcp sock, state: %s", tcp_state_str[child->state]);
			tcp_hash(child);
			tcp_sock_accept_enqueue(child);
			tcp_send_control_packet(child, TCP_SYN | TCP_ACK);
		}
		break;

	case TCP_SYN_SENT:
		log(DEBUG, "received packet in TCP_SYN_SENT state");

		if(cb->flags == TCP_SYN || 
			cb->flags == (TCP_SYN | TCP_ACK)){
			tcp_set_state(tsk, TCP_ESTABLISHED);
			tcp_update_window_safe(tsk, cb);
			tcp_unset_retrans_timer(tsk);
			tsk->rcv_nxt = cb->seq + 1;  // 设置期望收到的下一个序列号
        	// tsk->snd_una = cb->ack;      // 确认已经收到的序列号
        	// tsk->snd_nxt = tsk->snd_una; // 更新下一个要发送的序列号
			tcp_send_control_packet(tsk, TCP_ACK);
			wake_up(tsk->wait_connect);
		}
		else{
			char buf[32];
			tcp_copy_flags_to_str(cb->flags, buf);
			log(ERROR, "expect flag SYN | ACK, but"
				"get unhandled flag %s", buf);
		}
		break;

	case TCP_SYN_RECV:
		log(DEBUG, "received packet in TCP_SYN_RECV state");

		if(cb->flags == TCP_ACK){
			//tsk->snd_una = cb->ack;
			tcp_update_window_safe(tsk, cb);
			tcp_set_state(tsk, TCP_ESTABLISHED);
			tcp_unset_retrans_timer(tsk);
			wake_up(tsk->parent->wait_accept);
		}
		else{
			char buf[32];
			tcp_copy_flags_to_str(cb->flags, buf);
			log(ERROR, "expect flag ACK, but"
				"get unhandled flag %s", buf);
		}
		break;

	case TCP_ESTABLISHED:
		//log(DEBUG, "received packet in TCP_ESTABLISHED state");
		// char buf[32];
		// tcp_copy_flags_to_str(cb->flags, buf);
		// log(DEBUG, "get flag %s", buf);
		if(cb->flags == TCP_FIN){
			tcp_update_window_safe(tsk, cb);
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
			wake_up(tsk->wait_recv);
		}
		else if(cb->flags & TCP_ACK && tsk->rcv_nxt == cb->seq){
			if(cb->pl_len > 0){
				// 找到TCP数据部分的位置
				struct iphdr *ip = packet_to_ip_hdr(packet);
				struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);
				char *tcp_data = (char *)tcp + TCP_BASE_HDR_SIZE;
				// 复制数据到环形储存部分
				if(cb->pl_len > tsk->rcv_wnd){
					log(ERROR, "tcp receive buffer is full");
					tcp_send_reset(cb);
					return;
				}
				tcp_update_window_safe(tsk, cb);

				tcp_sock_read(tsk, tcp_data, cb->pl_len);

				tcp_send_control_packet(tsk, TCP_ACK);

				wake_up(tsk->wait_recv);
			}
			else if(cb->pl_len == 0) {
                tcp_update_window_safe(tsk, cb);
				struct tcphdr *k = packet_to_tcp_hdr(packet);
				log(DEBUG, "ack_num:%u", cb->ack);
				tcp_update_send_buffer(tsk,cb->ack);
				if(tsk->retrans_timer.enable) {
					tcp_update_retrans_timer(tsk);
				}
                //wake_up(tsk->wait_send);
            }

		}			
		else if(less_than_32b(tsk->rcv_nxt, cb->seq)){
			// 处理乱序到达的包
			log(DEBUG, "receive out of order packet");
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_recv_ofo_buffer_add_packet(tsk, packet, cb);
		}
		else if(less_or_equal_32b(cb->seq_end, tsk->rcv_nxt)){
			// 处理重复到达的包
			log(DEBUG, "receive repetitive packet");
			//tcp_update_window_safe(tsk, cb);
			tcp_send_control_packet(tsk, TCP_ACK);
		}
		break;

	case TCP_LAST_ACK:
		if(cb->flags == TCP_ACK){
			tcp_set_state(tsk, TCP_CLOSED);
			tcp_unset_retrans_timer(tsk);
			tcp_unhash(tsk);
			free_tcp_sock(tsk);
		}
		else{
			char buf[32];
			tcp_copy_flags_to_str(cb->flags, buf);
			log(ERROR, "expect flag ACK, but"
				"get unhandled flag %s", buf);
		}
		break;

	case TCP_FIN_WAIT_1:
		if(cb->flags == TCP_ACK || cb->flags == TCP_FIN ||
			cb->flags == (TCP_FIN | TCP_ACK)){
			//tsk->rcv_nxt = cb->seq + 1;
			tcp_update_window_safe(tsk, cb);
			tcp_set_state(tsk, TCP_FIN_WAIT_2);
		}
		else{
			char buf[32];
			tcp_copy_flags_to_str(cb->flags, buf);
			log(ERROR, "expect flag ACK, but"
				"get unhandled flag %s", buf);
			}
		break;

	case TCP_FIN_WAIT_2:	
		if(cb->flags & TCP_FIN){
			tcp_update_window_safe(tsk, cb);
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_unset_retrans_timer(tsk);
			wake_up(tsk->wait_recv);
		}
		else{
			char buf[32];
			tcp_copy_flags_to_str(cb->flags, buf);
			log(ERROR, "expect flag FIN | ACK, but"
				"get unhandled flag %s", buf);
		}
		break;

	default:
		log(ERROR, "unhandled tcp state %s, please implement", tcp_state_to_str(tsk->state));
		break;
	}

	pthread_mutex_unlock(&tsk->sk_lock);
}
