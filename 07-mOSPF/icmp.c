#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// icmp_send_packet has two main functions:
// 1.handle icmp packets sent to the router itself (ICMP ECHO REPLY).
// 2.when an error occurs, send icmp error packets.
// Note that the structure of these two icmp packets is different, you need to malloc different sizes of memory.
// Some function and macro definitions in ip.h/icmp.h can help you.
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	//log(DEBUG, "Sending ICMP packet");
	struct iphdr *ip;
	struct icmphdr *icmp;
	struct iphdr *in_ip = packet_to_ip_hdr(in_pkt);
	struct icmphdr *in_icmp = (struct icmphdr *)IP_DATA(in_ip);
	struct ether_header *eh = (struct ether_header *)in_pkt;
	int snd_len = len;

	switch (type)
	{
		case ICMP_ECHOREPLY:
			snd_len = len - ETHER_HDR_SIZE;
			ip = malloc(snd_len);
			ip->ihl = 5;
			icmp = (struct icmphdr *)IP_DATA(ip);
			memcpy(icmp, in_icmp, snd_len - IP_HDR_SIZE(in_ip));
			icmp->type = ICMP_ECHOREPLY;
			icmp->code = 0;
			icmp->checksum = icmp_checksum(icmp, snd_len - IP_HDR_SIZE(in_ip));

			ip_init_hdr(ip, ntohl(in_ip->daddr), ntohl(in_ip->saddr), snd_len, \
				IPPROTO_ICMP);

			break;

		case ICMP_DEST_UNREACH:
		case ICMP_TIME_EXCEEDED:
			int ori_iplen = IP_HDR_SIZE(in_ip);
			snd_len = IP_BASE_HDR_SIZE + ori_iplen + ICMP_HDR_SIZE + \
				ICMP_COPIED_DATA_LEN;
			ip = malloc(snd_len);
			ip->ihl = 5;
			icmp = (struct icmphdr *)IP_DATA(ip);
			memset(icmp, 0, ICMP_HDR_SIZE);
			icmp->type = type;
			icmp->code = code;

			// memcpy((char*)icmp + ICMP_HDR_SIZE, in_ip, ori_iplen);
			// memcpy((char*)icmp + ICMP_HDR_SIZE + ori_iplen, in_icmp, \
			// 	ICMP_COPIED_DATA_LEN);

			memcpy((char*)icmp + ICMP_HDR_SIZE, (char*)in_ip,\
				ori_iplen + ICMP_COPIED_DATA_LEN);
			// memcpy((char*)icmp + ICMP_HDR_SIZE + ori_iplen, in_icmp, \
			// 	ICMP_COPIED_DATA_LEN);
			icmp->checksum = icmp_checksum(icmp, ICMP_HDR_SIZE + ori_iplen + \
				ICMP_COPIED_DATA_LEN);

			ip_init_hdr(ip, ntohl(in_ip->daddr), ntohl(in_ip->saddr), \
				snd_len, IPPROTO_ICMP);

			break;
	}
	//log(DEBUG, "sending from %u to %u", ntohl(ip->saddr), ntohl(ip->daddr));
	ip_send_packet(ip, snd_len);
	free(ip);
}
