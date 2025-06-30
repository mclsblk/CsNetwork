#ifndef __TCP_SOCK_H__
#define __TCP_SOCK_H__

#include "types.h"
#include "list.h"
#include "tcp.h"
#include "tcp_timer.h"
#include "ring_buffer.h"

#include "synch_wait.h"

#include <pthread.h>

#define PORT_MIN	12345
#define PORT_MAX	23456

struct sock_addr {
	u32 ip;
	u16 port;
} __attribute__((packed));

struct send_buffer_entry {
	struct list_head list;
	u32 seq;
	int len;
	char *data;
};

struct recv_ofo_buf_entry{
	struct list_head list;
	u32 seq, seq_end;
	int len;
	char *data;
};

// the main structure that manages a connection locally
struct tcp_sock {
	// sk_ip, sk_sport, sk_sip, sk_dport are the 4-tuple that represents a 
	// connection
	struct sock_addr local;
	struct sock_addr peer;
#define sk_sip local.ip
#define sk_sport local.port
#define sk_dip peer.ip
#define sk_dport peer.port

	// pointer to parent tcp sock, a tcp sock which bind and listen to a port 
	// is the parent of tcp socks when *accept* a connection request
	struct tcp_sock *parent;

	// represents the number that the tcp sock is referred, if this number 
	// decreased to zero, the tcp sock should be released
	int ref_cnt;

	// hash_list is used to hash tcp sock into listen_table or established_table, 
	// bind_hash_list is used to hash into bind_table
	struct list_head hash_list;
	struct list_head bind_hash_list;

	// when a passively opened tcp sock receives a SYN packet, it mallocs a child 
	// tcp sock to serve the incoming connection, which is pending in the 
	// listen_queue of parent tcp sock
	struct list_head listen_queue;
	// when receiving the last packet (ACK) of the 3-way handshake, the tcp sock 
	// in listen_queue will be moved into accept_queue, waiting for *accept* by 
	// parent tcp sock
	struct list_head accept_queue;


#define TCP_MAX_BACKLOG 128
	// the number of pending tcp sock in accept_queue
	int accept_backlog;
	// the maximum number of pending tcp sock in accept_queue
	int backlog;

	// the list node used to link listen_queue or accept_queue of parent tcp sock
	struct list_head list;
	// tcp timer used during TCP_TIME_WAIT state
	struct tcp_timer timewait;

	// used for timeout retransmission
	struct tcp_timer retrans_timer;

	// synch waiting structure of *connect*, *accept*, *recv*, and *send*
	struct synch_wait *wait_connect;
	struct synch_wait *wait_accept;
	struct synch_wait *wait_recv;
	struct synch_wait *wait_send;

	// receiving buffer
	struct ring_buffer *rcv_buf;
	// used to pend unacked packets
	struct list_head send_buf;
	// used to pend out-of-order packets
	struct list_head rcv_ofo_buf;

	// tcp state, see enum tcp_state in tcp.h
	int state;

	// initial sending sequence number
	u32 iss;

	// the highest byte that is ACKed by peer
	u32 snd_una;
	// the highest byte sent
	u32 snd_nxt;

	// the highest byte ACKed by itself (i.e. the byte expected to receive next)
	u32 rcv_nxt;

	// used to indicate the end of fast recovery
	u32 recovery_point;		

	// min(adv_wnd, cwnd)
	u32 snd_wnd;
	// the receiving window advertised by peer
	u16 adv_wnd;

	// the size of receiving window (advertised by tcp sock itself)
	u16 rcv_wnd;

	// congestion window
	u32 cwnd;

	// slow start threshold
	u32 ssthresh;

	pthread_mutex_t sk_lock;
	pthread_mutex_t rcv_buf_lock;
	pthread_mutex_t send_buf_lock;
};

void tcp_set_state(struct tcp_sock *tsk, int state);

int tcp_sock_accept_queue_full(struct tcp_sock *tsk);
void tcp_sock_accept_enqueue(struct tcp_sock *tsk);
struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk);

int tcp_hash(struct tcp_sock *tsk);
void tcp_unhash(struct tcp_sock *tsk);
void tcp_bind_unhash(struct tcp_sock *tsk);
struct tcp_sock *alloc_tcp_sock();
void free_tcp_sock(struct tcp_sock *tsk);
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb);

u32 tcp_new_iss();

void tcp_send_reset(struct tcp_cb *cb);

void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags);
void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len);
int tcp_send_data(struct tcp_sock *tsk, char *buf, int len);

void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);

void init_tcp_stack();

int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr);
int tcp_sock_listen(struct tcp_sock *tsk, int backlog);
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr);
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk);
void tcp_sock_close(struct tcp_sock *tsk);

int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len);
int tcp_sock_write(struct tcp_sock *tsk, char *buf, long len);

#define TCP_MSS (ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE)

// 使用tsk->snd_una, tsk->snd_wnd, tsk->snd_nxt计算剩余窗口大小，如果大于TCP_MSS，则返回1，否则返回0
int tcp_tx_window_test(struct tcp_sock *tsk);

void tcp_send_probe_packet(struct tcp_sock *tsk);

/*
创建send_buffer_entry加入send_buf尾部

注意上锁，后面不再强调。
*/
void tcp_send_buffer_add_packet(struct tcp_sock *tsk, char *packet, int len);

/*
基于收到的ACK包，遍历发送队列，将已经接收的数据包从队列中移除

提取报文的tcp头可以使用packet_to_tcp_hdr，注意报文中的字段是大端序
*/
void tcp_update_send_buffer(struct tcp_sock *tsk, u32 ack);

/*
获取重传队列第一个包，修改ack号和checksum并通过ip_send_packet发送。

注意不要更新snd_nxt之类的参数，这是一个独立的重传报文。ip_send_packet会释放传入的指针，因而需要拷贝需要重传的报文。
*/
int tcp_retrans_send_buffer(struct tcp_sock *tsk);

/*
1. 创建recv_ofo_buf_entry
2. 用list_for_each_entry_safe遍历rcv_ofo_buf，将表项插入合适的位置。如果发现了重复数据包，则丢弃当前数据。
3. 调用tcp_move_recv_ofo_buffer执行报文上送
*/
int tcp_recv_ofo_buffer_add_packet(struct tcp_sock *tsk, char* packet, struct tcp_cb *cb);

/*
遍历rcv_ofo_buf，将所有有序的（序列号等于tsk->rcv_nxt）的报文送入接收队列（tsk->rcv_buf）
更新rcv_nxt, rcv_wnd并唤醒接收线程(wait_recv)

如果接收队列已满，应当退出函数，而非等待。
*/
int tcp_move_recv_ofo_buffer(struct tcp_sock *tsk);


///
void tcp_init_hdr(struct tcphdr *tcp, u16 sport, u16 dport, u32 seq, u32 ack,
	u8 flags, u16 rwnd);
#endif
