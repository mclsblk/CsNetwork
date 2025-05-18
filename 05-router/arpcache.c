#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweep thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// look up the IP->mac mapping, need pthread_mutex_lock/unlock
// Traverse the table to find whether there is an entry with the same IP and mac address with the given arguments.
// use host byte order for looking up ip address
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	// log(DEBUG, "try lookup");
	int lock = 0;
	if(pthread_mutex_trylock(&arpcache.lock) != 0) lock = 1;
	// log(DEBUG, "lookup %u", ip4);
	int i;
	for (i = 0; i < MAX_ARP_SIZE; i++) {
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4) {
			memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
			arpcache.entries[i].added = time(NULL);
			// log(DEBUG, "lookup succ");
			if(lock == 0) pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
	if(lock == 0) pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// insert the IP->mac mapping into arpcache, need pthread_mutex_lock/unlock
// If there is a timeout entry (attribute valid in struct) in arpcache, replace it.
// If there isn't a timeout entry in arpcache, randomly replace one.
// If there are pending packets waiting for this mapping, fill the ethernet header for each of them, and send them out.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(用arp_req结构体封装)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	// log(DEBUG, "try insert");
	pthread_mutex_lock(&arpcache.lock);
	int i = 0;
	for (i = 0; i < MAX_ARP_SIZE; i++)
		if (arpcache.entries[i].ip4 == ip4) break;
	if(i == MAX_ARP_SIZE)
		for (i = 0; i < MAX_ARP_SIZE; i++) 
			if (arpcache.entries[i].valid == 0) break;
	if(i == MAX_ARP_SIZE)
		i = rand() % MAX_ARP_SIZE;

	arpcache.entries[i].ip4 = ip4;
	memcpy(arpcache.entries[i].mac, mac, ETH_ALEN);
	arpcache.entries[i].added = time(NULL);
	arpcache.entries[i].valid = 1;

	// log(DEBUG, "inserted %u to MAC address: %02x:%02x:%02x:%02x:%02x:%02x",\
	// 	 ip4, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);


	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		// log(DEBUG, "req_entry %u", req_entry->ip4);
		// log(DEBUG, "entry %u\n", ip4);
		if (req_entry->ip4 == ip4) {
			struct cached_pkt *pkt_entry = NULL, *pkt_q;
			list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
				// struct ether_arp *hdr = packet_to_ether_arp(pkt_entry->packet);
				// memcpy(hdr->arp_tha, mac, ETH_ALEN);
				// hdr->arp_tpa = htonl(ip4);
				
				struct ether_header *eh = (struct ether_header *)pkt_entry->packet;
				memcpy(eh->ether_dhost, mac, ETH_ALEN);
				eh->ether_type = htons(ETH_P_IP);
				//memcpy(eh->ether_shost, req_entry->iface->mac, ETH_ALEN);

				// send the packet
				iface_send_packet(req_entry->iface, pkt_entry->packet, pkt_entry->len);
				list_delete_entry(&(pkt_entry->list));
				//free(pkt_entry->packet);
				free(pkt_entry);
			}
			
			// list_delete_entry(&(req_entry->list));
			// free(req_entry);
			break;
		}
	}
	//log(DEBUG, "pending packets sent");
	pthread_mutex_unlock(&arpcache.lock);
	return;
}

// append the packet to arpcache
// Look up in the list which stores pending packets, if there is already an entry with the same IP address and iface, 
// which means the corresponding arp request has been sent out, just append this packet at the tail of that entry (The entry may contain more than one packet).
// Otherwise, malloc a new entry with the given IP address and iface, append the packet, and send arp request.
// Tips:
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	struct arp_req *req_entry = NULL;
	int find = 0;
	pthread_mutex_lock(&arpcache.lock);
	list_for_each_entry(req_entry, &(arpcache.req_list), list) {
		if(req_entry->ip4 == ip4 && req_entry->iface == iface){
			// log(DEBUG, "append to old list");
			find = 1;
			break;
		}
	}	

	if(find == 0){
		// log(DEBUG, "append new list");
		req_entry = malloc(sizeof(struct arp_req));
		req_entry->iface = iface;
		req_entry->ip4 = ip4;
		req_entry->sent = time(NULL);
		req_entry->retries = 1;
		init_list_head(&(req_entry->cached_packets));
		list_add_tail(&(req_entry->list), &(arpcache.req_list));
	}
	pthread_mutex_unlock(&arpcache.lock);
	
	struct cached_pkt *pkt_entry = malloc(sizeof(struct cached_pkt));
	pkt_entry->packet = malloc(len);
	memcpy(pkt_entry->packet, packet, len);
	pkt_entry->len = len;
	list_add_tail(&(pkt_entry->list), &(req_entry->cached_packets));

	// log(DEBUG, "append packet to list");
	if(find == 0) arp_send_request(iface, ip4);
	return;
}

// sweep arpcache periodically
// for IP->mac entry, if the entry has been in the table for more than 15 seconds, remove it from the table
// for pending packets, if the arp request is sent out 1 second ago, while the reply has not been received, retransmit the arp request
// If the arp request has been sent 5 times without receiving arp reply, for each pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these packets
// tips
// arpcache_t是完整的arp缓存表，里边的req_list是一个链表，它的每个节点(类型是arp_req)里又存着一个链表头，这些二级链表(节点类型是cached_pkt)缓存着相同目标ip但不知道mac地址的包
void *arpcache_sweep(void *arg) 
{
	while (1) {
		// log(DEBUG, "sweep");
		sleep(1);
		pthread_mutex_lock(&arpcache.lock);
		time_t now = time(NULL);
		int i;
		for (i = 0; i < MAX_ARP_SIZE; i++) {
			if (arpcache.entries[i].valid && now - arpcache.entries[i].added > ARP_ENTRY_TIMEOUT) {
				arpcache.entries[i].valid = 0;
			}
		}
		struct arp_req *req_entry = NULL, *req_q;
		list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
			if(req_entry->sent + 1 < now){
				if(req_entry->retries <= ARP_REQUEST_MAX_RETRIES){
					req_entry->retries++;
					// log(DEBUG, "retries: %d", req_entry->retries);
					pthread_mutex_unlock(&arpcache.lock);
					arp_send_request(req_entry->iface, req_entry->ip4);
					req_entry->sent = now;
					pthread_mutex_lock(&arpcache.lock);
				}
				else{
					pthread_mutex_unlock(&arpcache.lock);
					// log(DEBUG, "retries exceeded, sending icmp packet");
					struct cached_pkt *pkt_entry = NULL, *pkt_q;
					list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
						icmp_send_packet(pkt_entry->packet, pkt_entry->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
						list_delete_entry(&(pkt_entry->list));
						free(pkt_entry->packet);
						free(pkt_entry);
					}
					list_delete_entry(&(req_entry->list));
					free(req_entry);
					pthread_mutex_lock(&arpcache.lock);
				}
			}
		}
		pthread_mutex_unlock(&arpcache.lock);
	}
}