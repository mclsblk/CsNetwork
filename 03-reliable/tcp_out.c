#include "tcp.h"
#include "tcp_sock.h"
#include "ip.h"
#include "ether.h"

#include "log.h"
#include "list.h"

#include <stdlib.h>
#include <string.h>

// initialize tcp header according to the arguments
void tcp_init_hdr(struct tcphdr *tcp, u16 sport, u16 dport, u32 seq, u32 ack,
		u8 flags, u16 rwnd)
{
	memset((char *)tcp, 0, TCP_BASE_HDR_SIZE);

	tcp->sport = htons(sport);
	tcp->dport = htons(dport);
	tcp->seq = htonl(seq);
	tcp->ack = htonl(ack);
	tcp->off = TCP_HDR_OFFSET;
	tcp->flags = flags;
	tcp->rwnd = htons(rwnd);
}

// send a tcp packet
//
// Given that the payload of the tcp packet has been filled, initialize the tcp 
// header and ip header (remember to set the checksum in both header), and emit 
// the packet by calling ip_send_packet.
void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len) 
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	int ip_tot_len = len - ETHER_HDR_SIZE;
	int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

	u32 saddr = tsk->sk_sip;
	u32	daddr = tsk->sk_dip;
	u16 sport = tsk->sk_sport;
	u16 dport = tsk->sk_dport;

	u32 seq = tsk->snd_nxt;
	u32 ack = tsk->rcv_nxt;
	u16 rwnd = tsk->rcv_wnd;

	tcp_init_hdr(tcp, sport, dport, seq, ack, TCP_PSH|TCP_ACK, rwnd);
	ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP); 

	tcp->checksum = tcp_checksum(ip, tcp);

	ip->checksum = ip_checksum(ip);

	tsk->snd_nxt += tcp_data_len;

	char *buf_copy = malloc(len);  // 堆分配
    memcpy(buf_copy, packet, len);
    tcp_send_buffer_add_packet(tsk, buf_copy, len);
    free(buf_copy); 
	//log(DEBUG, "added_packet_buf");
	ip_send_packet(packet, len);
	//log(DEBUG, "tcp_send_packet");
	if (!tsk->retrans_timer.enable) {
		tcp_set_retrans_timer(tsk);
	}
	else{
		tcp_update_retrans_timer(tsk);
	}
}

// send a tcp control packet
//
// The control packet is like TCP_ACK, TCP_SYN, TCP_FIN (excluding TCP_RST).
// All these packets do not have payload and the only difference among these is 
// the flags.
void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);
	if (!packet) {
		log(ERROR, "malloc tcp control packet failed.");
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;

	ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip, tot_len, IPPROTO_TCP);
	tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport, tsk->snd_nxt, \
			tsk->rcv_nxt, flags, tsk->rcv_wnd);

	tcp->checksum = tcp_checksum(ip, tcp);

	if (flags & (TCP_SYN|TCP_FIN)){	
		tsk->snd_nxt += 1;
		tcp_set_retrans_timer(tsk);

		tcp_send_buffer_add_packet(tsk, "0", 1);
	}

	log(DEBUG, "sent arguments: seq = %u, ack = %u", tsk->snd_nxt, tsk->rcv_nxt);
	ip_send_packet(packet, pkt_size);
}

// send tcp reset packet
//
// Different from tcp_send_control_packet, the fields of reset packet is 
// from tcp_cb instead of tcp_sock.
void tcp_send_reset(struct tcp_cb *cb)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);
	if (!packet) {
		log(ERROR, "malloc tcp control packet failed.");
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	ip_init_hdr(ip, cb->daddr, cb->saddr, tot_len, IPPROTO_TCP);
	tcp_init_hdr(tcp, cb->dport, cb->sport, 0, cb->seq_end, TCP_RST|TCP_ACK, 0);
	tcp->checksum = tcp_checksum(ip, tcp);

	ip_send_packet(packet, pkt_size);
}

/*
仿照tcp_send_packet函数，发送probe报文。几处改动：
1. 发送的序列号设置为一个已经ACK过的序列号（比如tsk->snd_una - 1）
2. 不需要更新snd_nxt
3. 不需要设置重传相关内容
4. TCP负载为一个任意的字节
*/
void tcp_send_probe_packet(struct tcp_sock *tsk){
	// 创建一个TCP包，包含一个字节的负载
    int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + 1;
    char *packet = malloc(pkt_size);
    if (!packet) {
        log(ERROR, "malloc tcp probe packet failed.");
        return;
    }

    struct iphdr *ip = packet_to_ip_hdr(packet);
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);
    char *tcp_data = (char *)tcp + TCP_BASE_HDR_SIZE;

    tcp_data[0] = 0xff;  // 探测数据

    // 设置IP头
    u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + 1;
    ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip, tot_len, IPPROTO_TCP);

    // 使用snd_una - 1作为序列号（一个已经确认过的序列号）
    u32 seq;
    if (tsk->snd_una > 0) {
        seq = tsk->snd_una - 1;
    } else {
        seq = 0;  // 如果snd_una为0，则使用0
    }

    // 设置TCP头
    tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport, seq, tsk->rcv_nxt, 
                 TCP_ACK, tsk->rcv_wnd);

    // 计算校验和
    tcp->checksum = tcp_checksum(ip, tcp);
    ip->checksum = ip_checksum(ip);

    // 发送包
    ip_send_packet(packet, pkt_size);

    log(DEBUG, "sent window probe packet, seq = %u", seq);
}