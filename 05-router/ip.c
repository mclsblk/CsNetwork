#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "log.h"
#include <stdlib.h>
#include <assert.h>

// If the packet is ICMP echo request and the destination IP address is equal to the IP address of the iface, send ICMP echo reply.
// Otherwise, forward the packet.
// Tips:
// You can use struct iphdr *ip = packet_to_ip_hdr(packet); in ip.h to get the ip header in a packet.
// You can use struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip); in ip.h to get the icmp header in a packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	//log(DEBUG, "Received IP packet");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
	u32 dst_ip = ntohl(ip->daddr);
	u32 src_ip = ntohl(ip->saddr);
	u32 iface_ip = iface->ip;
	u8 type = icmp->type;
	// log(DEBUG, "ip figures: from %u to %u this:%u",\
	// 	src_ip, dst_ip, iface_ip);
	if(dst_ip == iface_ip){
		//log(DEBUG, "Received ICMP packet destined to this router");
		if(type != ICMP_ECHOREQUEST){
			log(ERROR, "ICMP packet type %u is not ECHO REQUEST, dropping packet", type);
			return;
		}
		//log(DEBUG, "ICMP ECHO REQUEST received, sending ICMP ECHO REPLY");
		icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
	}
	else{
		//log(DEBUG, "Forwarding packet to %u", dst_ip);
		ip_forward_packet(dst_ip, packet, len);
	}
}

// When forwarding the packet, you should check the TTL, update the checksum and TTL.
// Then, determine the next hop to forward the packet, then send the packet by iface_send_packet_by_arp.
// The interface to forward the packet is specified by longest_prefix_match.
void ip_forward_packet(u32 ip_dst, char *packet, int len)
{
	//log(DEBUG, "Forwarding IP packet");
	struct iphdr *ip = packet_to_ip_hdr(packet);
	ip->ttl--;
	if(ip->ttl == 0){
		log(ERROR, "TTL expired, sending ICMP TIME EXCEEDED");
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		return;
	}
	ip->checksum = ip_checksum(ip);
	//log(DEBUG, "ip checksum updated");
	rt_entry_t *entry = longest_prefix_match(ip_dst);
	//log(DEBUG, "longest prefix match");
	if(entry == NULL){
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		return;
	}
	iface_info_t *iface = entry->iface;
	u32 nexthop = entry->gw ? entry->gw : ip_dst;
	//log(DEBUG, "comfirm next hop %u", nexthop);
	iface_send_packet_by_arp(iface, nexthop, packet, len);
}