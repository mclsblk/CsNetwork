#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// handle arp packet
// If the dest ip address of this arp packet is not equal to the ip address of the incoming iface, drop it.
// If it is an arp request packet, send arp reply to the destination, insert the ip->mac mapping into arpcache.
// If it is an arp reply packet, insert the ip->mac mapping into arpcache.
// Tips:
// You can use functions: htons, htonl, ntohs, ntohl to convert host byte order and network byte order (16 bits use ntohs/htons, 32 bits use ntohl/htonl).
// You can use function: packet_to_ether_arp() in arp.h to get the ethernet header in a packet.
void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *hdr = packet_to_ether_arp(packet);
	u32 dst_ip = ntohl(hdr->arp_tpa);
	u32 src_ip = ntohl(hdr->arp_spa);
	// log(DEBUG, "ARP packet from %u to %u", src_ip, dst_ip);
	u32 iface_ip = iface->ip;
	if (dst_ip != iface_ip)
	{
		log(ERROR, "ARP packet destination IP %u does not match interface IP %u, dropping packet",
			dst_ip, iface_ip);
		return;
	}
	u16 op = ntohs(hdr->arp_op);
	switch (op)
	{
	case ARPOP_REQUEST:
		//log(DEBUG, "ARP request received, sending ARP reply");
		arp_send_reply(iface, hdr);
		// log(DEBUG, "ARP reply sent");
		// insert the IP->mac mapping into arpcache
		arpcache_insert(ntohl(hdr->arp_spa), hdr->arp_sha);
		break;

	case ARPOP_REPLY:
		// log(DEBUG, "ARP reply received");
		// insert the IP->mac mapping into arpcache
		arpcache_insert(ntohl(hdr->arp_spa), hdr->arp_sha);
		break;

	default:
		break;
	}
}

// send an arp reply packet
// Encapsulate an arp reply packet, send it out through iface_send_packet.
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	//log(DEBUG, "Sending ARP reply");

	struct ether_arp *reply_hdr = malloc(sizeof(struct ether_arp));
	reply_hdr->arp_hrd = htons(ARPHRD_ETHER);
	reply_hdr->arp_pro = htons(ETH_P_IP);
	reply_hdr->arp_hln = ETH_ALEN;
	reply_hdr->arp_pln = 4;

	reply_hdr->arp_op = htons(ARPOP_REPLY);
	memcpy(reply_hdr->arp_sha, iface->mac, ETH_ALEN);
	memcpy(reply_hdr->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	reply_hdr->arp_spa = req_hdr->arp_tpa;
	reply_hdr->arp_tpa = req_hdr->arp_spa;

	char *packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header *eh = (struct ether_header *)packet;
	eh->ether_type = htons(ETH_P_ARP);
	memcpy(eh->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);

	memcpy(packet_to_ether_arp(packet), reply_hdr, sizeof(struct ether_arp));
	//log(DEBUG, "Sending ARP reply");
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
	//free(packet);
	free(reply_hdr);
}

// send an arp request
// Encapsulate an arp request packet, send it out through iface_send_packet.
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	struct ether_arp *hdr = malloc(sizeof(struct ether_arp));
	hdr->arp_hrd = htons(ARPHRD_ETHER);
	hdr->arp_pro = htons(ETH_P_IP);
	hdr->arp_hln = ETH_ALEN;
	hdr->arp_pln = 4;
	hdr->arp_op = htons(ARPOP_REQUEST);
	memcpy(hdr->arp_sha, iface->mac, ETH_ALEN);
	hdr->arp_spa = htonl(iface->ip);
	hdr->arp_tpa = htonl(dst_ip);
	static u8 BROADCAST_MAC[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	memcpy(hdr->arp_tha, BROADCAST_MAC, ETH_ALEN);

	char *packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_header *eh = (struct ether_header *)packet;
	eh->ether_type = htons(ETH_P_ARP);
	memcpy(eh->ether_dhost, BROADCAST_MAC, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);

	memcpy(packet + ETHER_HDR_SIZE, hdr, sizeof(struct ether_arp));
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));

	//log(DEBUG, "Sent Request");
	free(hdr);	
}

// send (IP) packet through arpcache lookup
// Lookup the mac address of dst_ip in arpcache.
// If it is found, fill the ethernet header and emit the packet by iface_send_packet.
// Otherwise, pending this packet into arpcache and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	//log(DEBUG, "Sending packet arp");
	u8 mac[ETH_ALEN];
	int ret = arpcache_lookup(dst_ip, mac);
	//log(DEBUG, "find succ: %d", ret);
	if (ret == 1)
	{
		struct ether_header *eh = (struct ether_header *)packet;
		memcpy(eh->ether_dhost, mac, ETH_ALEN);
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		eh->ether_type = htons(ETH_P_IP);
		iface_send_packet(iface, packet, len);
		//log(DEBUG, "Sent packet to %u", dst_ip);
		// log(DEBUG, "MAC address: %02x:%02x:%02x:%02x:%02x:%02x",
		// 	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
	else
	{
		// log(DEBUG, "append");
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
