#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include "rtable.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();

	mospf_db_entry_t *db_entry = malloc(sizeof(*db_entry));
	db_entry->rid = instance->router_id;
	db_entry->seq = 0;
	db_entry->nadv = 0;
	db_entry->alive = 0;
	// 计算直连网络数量
	int nadv = 0;
	list_for_each_entry(iface, &instance->iface_list, list) {
		nadv++;
	}
	
	db_entry->nadv = nadv;
	if (nadv > 0) {
		db_entry->array = malloc(nadv * MOSPF_LSA_SIZE);
		int i = 0;
		list_for_each_entry(iface, &instance->iface_list, list) {
			db_entry->array[i].network = iface->ip & iface->mask; // 主机字节序
			db_entry->array[i].mask = iface->mask;
			db_entry->array[i].rid = 0; // 直连网络的rid为0
			i++;
		}
	} else {
		db_entry->array = NULL;
	}
	list_add_tail(&db_entry->list, &mospf_db);
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);
void send_all_nbr_by_iface(iface_info_t* iface, char* packet, int len);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	
	while(1){
		pthread_mutex_lock(&mospf_lock);
		// log(INFO, "sending mospf hello packet");
		int tot_len = MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE + IP_BASE_HDR_SIZE;
		char *packet = malloc(tot_len);
		struct iphdr *ip = malloc(IP_BASE_HDR_SIZE);
		struct mospf_hdr mospf;
		struct mospf_hello hello;
		iface_info_t *iface = NULL;

		list_for_each_entry(iface, &instance->iface_list, list) {	
			ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters,
				MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE + IP_BASE_HDR_SIZE, 
				IPPROTO_MOSPF);	
			mospf_init_hdr(&mospf, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE,
				instance->router_id, instance->area_id);
			mospf_init_hello(&hello, iface->mask);

			memcpy(packet, ip, IP_BASE_HDR_SIZE);			
			memcpy(packet + IP_BASE_HDR_SIZE, &mospf, MOSPF_HDR_SIZE);	
			memcpy(packet + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE, 
				&hello, MOSPF_HELLO_SIZE);


			struct mospf_hdr *packet_mospf = (struct mospf_hdr *)(packet + IP_BASE_HDR_SIZE);
            packet_mospf->checksum = 0;  // 先清零
            packet_mospf->checksum = mospf_checksum(packet_mospf);

			char *ether_packet = malloc(ETHER_HDR_SIZE + tot_len);
			memcpy(ether_packet + ETHER_HDR_SIZE, packet, tot_len);
			struct ether_header *eh = (struct ether_header *)ether_packet;
            
            // 设置源MAC地址
            memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
            
			// 在sending_mospf_hello_thread和send_all_nbr_by_iface函数中，将多播MAC改为广播MAC
			static u8 BROADCAST_MAC[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
			memcpy(eh->ether_dhost, BROADCAST_MAC, ETH_ALEN);

            // 计算多播MAC地址: 01:00:5E + IP地址的低23位
			// u32 dst = MOSPF_ALLSPFRouters & 0x7FFFFF; // 低23位
            // eh->ether_dhost[0] = 0x01;
            // eh->ether_dhost[1] = 0x00;
            // eh->ether_dhost[2] = 0x5E;
            // eh->ether_dhost[3] = (dst & 0x007F0000) >> 16;
            // eh->ether_dhost[4] = (dst & 0x0000FF00) >> 8;
            // eh->ether_dhost[5] = (dst & 0x000000FF);
            
            eh->ether_type = htons(ETH_P_IP);

			iface_send_packet(iface, ether_packet, ETHER_HDR_SIZE + tot_len);
		}
		free(packet);
		free(ip);
		pthread_mutex_unlock(&mospf_lock);
		// log(INFO, "sent mospf hello packet");
		sleep(MOSPF_DEFAULT_HELLOINT);		
	}


	return NULL;
}

void send_mospf_lsu_update(){
	// log(INFO, "sending mospf lsu update");
	struct mospf_hdr mospf;
	struct mospf_lsu lsu;
  	struct mospf_lsa *lsa = NULL;
	int nlsa = 0;
	instance->sequence_num += 1;
	
	mospf_db_entry_t *pos;
	list_for_each_entry(pos, &mospf_db, list){
		if(pos->rid == instance->router_id){
			nlsa += pos->nadv;
			if(nlsa > 0){
				lsa = malloc(nlsa * MOSPF_LSA_SIZE);
				for (int i = 0; i < pos->nadv; i++) {
					lsa[i].network = htonl(pos->array[i].network);
                    lsa[i].mask = htonl(pos->array[i].mask);
                    lsa[i].rid = htonl(pos->array[i].rid);
				}
			}
			break;
		}
	}

	if(lsa == NULL || nlsa == 0){
		// log(INFO, "no LSA to send, skipping LSU update");
		return; // No LSA to send, skip LSU update
	}

	mospf_init_hdr(&mospf, MOSPF_TYPE_LSU, MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nlsa * MOSPF_LSA_SIZE,
			instance->router_id, instance->area_id);
	mospf_init_lsu(&lsu, nlsa);

	char* packet = malloc(IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nlsa * MOSPF_LSA_SIZE);
	memcpy(packet + IP_BASE_HDR_SIZE, &mospf, MOSPF_HDR_SIZE);
	memcpy(
		packet + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE, 
		&lsu, MOSPF_LSU_SIZE
	);
	memcpy(
		packet + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE, 
		lsa, nlsa * MOSPF_LSA_SIZE
	);

	struct mospf_hdr *packet_mospf = (struct mospf_hdr *)(packet + IP_BASE_HDR_SIZE);
    packet_mospf->checksum = 0;  // 先清零
    packet_mospf->checksum = mospf_checksum(packet_mospf); 

	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		char *iface_packet = malloc(IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nlsa * MOSPF_LSA_SIZE);
		memcpy(iface_packet, packet, IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nlsa * MOSPF_LSA_SIZE);
		send_all_nbr_by_iface(iface, iface_packet, 
			IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + nlsa * MOSPF_LSA_SIZE);
		free(iface_packet);
	}
	// log(INFO, "sent mospf lsu update to all neighbors on interface");
		
	free(lsa);
	free(packet);
}

void send_all_nbr_by_iface(iface_info_t* iface, char* packet, int len){
	if (iface->mask == 0) {
		log(ERROR, "interface %s has no mask, skipping LSU", iface->name);
		return; // skip interfaces with no mask
	}
	// log(INFO, "sending mospf lsu update to all neighbors on interface %s", iface->name);
	mospf_nbr_t *nbr = NULL;
	struct iphdr *ip = malloc(IP_BASE_HDR_SIZE);
	char *nbr_packet = malloc(len);
	memcpy(nbr_packet, packet, len);
	ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters, len, IPPROTO_MOSPF);
	memcpy(nbr_packet, ip, IP_BASE_HDR_SIZE);
	int tot_len = len + ETHER_HDR_SIZE;
	char *ether_packet = malloc(ETHER_HDR_SIZE + tot_len);
	memcpy(ether_packet + ETHER_HDR_SIZE, nbr_packet, tot_len);
	struct ether_header *eh = (struct ether_header *)ether_packet;
	
	// 设置源MAC地址
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	
	// 在sending_mospf_hello_thread和send_all_nbr_by_iface函数中，将多播MAC改为广播MAC
	static u8 BROADCAST_MAC[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	memcpy(eh->ether_dhost, BROADCAST_MAC, ETH_ALEN);

	// 计算多播MAC地址: 01:00:5E + IP地址的低23位
	// u32 dst = MOSPF_ALLSPFRouters & 0x7FFFFF; // 低23位
	// eh->ether_dhost[0] = 0x01;
	// eh->ether_dhost[1] = 0x00;
	// eh->ether_dhost[2] = 0x5E;
	// eh->ether_dhost[3] = (dst & 0x007F0000) >> 16;
	// eh->ether_dhost[4] = (dst & 0x0000FF00) >> 8;
	// eh->ether_dhost[5] = (dst & 0x000000FF);
	
	eh->ether_type = htons(ETH_P_IP);

	iface_send_packet(iface, ether_packet, ETHER_HDR_SIZE + tot_len);
	free(nbr_packet);
	free(ip);
}

void *checking_nbr_thread(void *param)
{
	iface_info_t *iface = NULL;

	while(1){			
		pthread_mutex_lock(&mospf_lock);
		int changed = 0;	
		// log(INFO, "checking neighbors");
		list_for_each_entry(iface, &instance->iface_list, list) {
			time_t now = time(NULL);
			mospf_nbr_t *pos, *n;
			list_for_each_entry_safe(pos, n, &iface->nbr_list, list) {
				if (pos->alive > MOSPF_HELLO_TIMEOUT) {
					// log(INFO, "neighbor timed out");
					changed = 1;
					mospf_db_entry_t *db_pos;
					list_for_each_entry(db_pos, &mospf_db, list) {
						if (db_pos->rid == instance->router_id) {
							// Remove the neighbor from the database
							if(db_pos->array == NULL) {
								// log(ERROR, "database entry for router %u has no advs", db_pos->rid);
								break;
							}
							for (int i = 0; i < db_pos->nadv; i++) {
								if (db_pos->array[i].rid == pos->nbr_id) {
									// Shift the remaining entries
									for (int j = i; j < db_pos->nadv - 1; j++) {
										db_pos->array[j] = db_pos->array[j + 1];
									}
									db_pos->nadv -= 1;
									db_pos->array = realloc(db_pos->array, db_pos->nadv * MOSPF_LSA_SIZE);
									break;
								}
							}
							break;
						}
					}
					list_delete_entry(&pos->list);
					free(pos);
				}
				else{
					pos->alive += 1;
				}
			}
		}
		// Send new nbr list to all neighbors
		if(changed == 1) {
			send_mospf_lsu_update();
			mospf_calculate_rtable();
		}
		pthread_mutex_unlock(&mospf_lock);
		sleep(6);
		// log(INFO, "new table");
		// print_rtable();
	}

	return NULL;
}

void *checking_database_thread(void *param)
{
	mospf_db_entry_t *pos, *n;
	int changed = 0;
		
	while(1){
		pthread_mutex_lock(&mospf_lock);
		// log(INFO, "checking mospf database entries");
		list_for_each_entry_safe(pos, n, &mospf_db, list) {
			if(pos->rid == instance->router_id) {
				continue; // Skip the database entry for the router itself
			}
			if (pos->alive > MOSPF_DATABASE_TIMEOUT) {
				// log(INFO, "database entry with rid %u timed out", pos->rid);
				list_delete_entry(&pos->list);
				if(pos->array != NULL) free(pos->array);
				free(pos);
				changed = 1;
			}
			else {
				pos->alive += 1;
			}
		}
		// log(INFO, "checking mospf database entries done");

		if (changed == 1) {
			// log(INFO, "mospf database changed, recalculating routing table");
			// Recalculate routing table if database has changed
			mospf_calculate_rtable();
			changed = 0;
		}
		
		pthread_mutex_unlock(&mospf_lock);
		sleep(5);
	}

	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	// log(INFO, "received mospf hello packet on interface %s", iface->name);
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_hello *hello = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);

    u32 src_ip = ntohl(ip->saddr);
    u32 rid = ntohl(mospf->rid);
    
    // 检查是否是来自自己的包
    if (rid == instance->router_id) {
        return;
    }
	pthread_mutex_lock(&mospf_lock);

	// 首先检查邻居是否已存在
    mospf_nbr_t *existing_nbr = NULL;
    list_for_each_entry(existing_nbr, &iface->nbr_list, list) {
        if (existing_nbr->nbr_id == ntohl(mospf->rid)) {
            // log(INFO, "neighbor %u already exists, updating alive timer", existing_nbr->nbr_id);
            existing_nbr->alive = 0; // 重置存活时间
            pthread_mutex_unlock(&mospf_lock);
            return;
        }
    }

	mospf_nbr_t *nbr = malloc(sizeof(*nbr));
	nbr->nbr_id = ntohl(mospf->rid);
	nbr->nbr_ip = ntohl(ip->saddr);
	nbr->nbr_mask = ntohl(hello->mask);
	nbr->alive = 0;


	mospf_db_entry_t *db_entry = NULL;
	list_for_each_entry(db_entry, &mospf_db, list) {
		if (db_entry->rid == instance->router_id) {
			// Check if the neighbor already exists in the database
			int found = 0;
			for (int i = 0; i < db_entry->nadv; i++) {
				if (db_entry->array[i].rid == nbr->nbr_id) {
					found = 1;
					db_entry->alive = 0; // Reset the alive timer
					free(nbr);
					break;
				}
			}

			if(found == 1){
				pthread_mutex_unlock(&mospf_lock);
				return; // Neighbor already exists in the database, no need to add
			}

			// Add the new neighbor to the database
			db_entry->nadv += 1;
			if(db_entry->array != NULL){
				db_entry->array = realloc(db_entry->array, db_entry->nadv * MOSPF_LSA_SIZE);
			}
			else{
				db_entry->array = malloc(db_entry->nadv * MOSPF_LSA_SIZE);          
			}
			db_entry->array[db_entry->nadv - 1].network = iface->ip & iface->mask;
            db_entry->array[db_entry->nadv - 1].mask = iface->mask;
            db_entry->array[db_entry->nadv - 1].rid = nbr->nbr_id;
			log(INFO, "added neighbor %u to the database", nbr->nbr_id);
			send_mospf_lsu_update();

			break;
		}
	}

	list_add_tail(&nbr->list, &iface->nbr_list);
	log(INFO, "add to iface nbr list");
	mospf_calculate_rtable();

	pthread_mutex_unlock(&mospf_lock);

}

void *sending_mospf_lsu_thread(void *param)
{
	while(1){
		pthread_mutex_lock(&mospf_lock);
		// log(INFO, "sending mospf lsu update");
		send_mospf_lsu_update();
		pthread_mutex_unlock(&mospf_lock);
		sleep(instance->lsuint);
	}

	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	// log(INFO, "received mospf lsu packet on interface %s", iface->name);
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_lsu *lsu = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
	int find = 0, changed = 0;
	u32 src_rid = ntohl(mospf->rid);
    u16 seq = ntohs(lsu->seq);
    u32 nadv = ntohl(lsu->nadv);
    
    // 检查是否是来自自己的LSU
    if (src_rid == instance->router_id) {
        // log(INFO, "received lsu from myself, ignoring");
        return;
    }

    if (nadv == 0) {
        // log(ERROR, "received lsu with no advs");
        return;
    }

	pthread_mutex_lock(&mospf_lock);

	mospf_db_entry_t *db_entry = NULL;
	list_for_each_entry(db_entry, &mospf_db, list) {
		if (db_entry->rid == src_rid) {
			if(db_entry->seq > seq) {
				// log(INFO, "received lsu with old seq %u, current seq %u, ignoring", seq, db_entry->seq);
				pthread_mutex_unlock(&mospf_lock);
				return; // Ignore old sequence numbers
			}
			db_entry->alive = 0; // Reset the alive timer
			db_entry->seq = seq;
			db_entry->nadv = nadv;
			db_entry->array = realloc(db_entry->array, db_entry->nadv * MOSPF_LSA_SIZE);
			for (int i = 0; i < db_entry->nadv; i++) {
				struct mospf_lsa *lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE + i * MOSPF_LSA_SIZE);
				if(db_entry->array[i].network != ntohl(lsa->network) ||
				   db_entry->array[i].mask != ntohl(lsa->mask) ||
				   db_entry->array[i].rid != ntohl(lsa->rid)) {
					db_entry->array[i].network = ntohl(lsa->network);
					db_entry->array[i].mask = ntohl(lsa->mask);
					db_entry->array[i].rid = ntohl(lsa->rid);
					changed = 1; // 有变化
				}
			}
			find = 1;
			break;
		}
	}

	if (find == 0) {
		db_entry = malloc(sizeof(mospf_db_entry_t));
		db_entry->rid = src_rid;
		db_entry->seq = seq;
		db_entry->nadv = nadv;
		db_entry->alive = 0;
		db_entry->array = malloc(db_entry->nadv * MOSPF_LSA_SIZE);
		for (int i = 0; i < db_entry->nadv; i++) {
			struct mospf_lsa *lsa = (struct mospf_lsa *)((char *)lsu + MOSPF_LSU_SIZE + i * MOSPF_LSA_SIZE);
			db_entry->array[i].network = ntohl(lsa->network);
			db_entry->array[i].mask = ntohl(lsa->mask);
			db_entry->array[i].rid = ntohl(lsa->rid);
		}
		list_add_tail(&db_entry->list, &mospf_db);
	}
	if(find == 0 || changed == 1) {
		//log(INFO, "mospf database updated for router %u", ntohl(mospf->rid));
		mospf_calculate_rtable();
	}

	// 所有其它接口转发包
	// Forward the packet to all interfaces except the one that received it
	if (lsu->ttl > 1) { // Only forward if TTL > 1 after decrement
		// Create a modified packet with decremented TTL
		int packet_len = len - ETHER_HDR_SIZE;
		char *modified_packet = malloc(packet_len);
		memcpy(modified_packet, packet + ETHER_HDR_SIZE, packet_len);
		
		// Update the TTL in the LSU header
		struct mospf_hdr *modified_mospf = (struct mospf_hdr *)(modified_packet + IP_BASE_HDR_SIZE);
		struct mospf_lsu *modified_lsu = (struct mospf_lsu *)((char *)modified_mospf + MOSPF_HDR_SIZE);
		modified_lsu->ttl = lsu->ttl - 1;
		
		// Recalculate checksum
		modified_mospf->checksum = 0;
		modified_mospf->checksum = mospf_checksum(modified_mospf);
		
		// Forward to all interfaces except the one that received the packet
		iface_info_t *other_iface;
		list_for_each_entry(other_iface, &instance->iface_list, list) {
			if (other_iface != iface) { // Skip the interface that received the packet
				send_all_nbr_by_iface(other_iface, modified_packet, packet_len);	
			}
		}			
		free(modified_packet);
	}

	pthread_mutex_unlock(&mospf_lock);
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	// log(INFO, "received mospf packet on interface %s", iface->name);
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_BASE_HDR_SIZE);

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}

void mospf_calculate_rtable()
{
    log(INFO, "calculating mospf routing table...");
    
    int INT_MAX = 2147483647;
    clear_rtable();

    // 首先添加直连路由
    iface_info_t *iface;
    list_for_each_entry(iface, &instance->iface_list, list) {
        u32 network = iface->ip & iface->mask;
        rt_entry_t *entry = new_rt_entry(network, iface->mask, 0, iface);
		mospf_db_entry_t *db_entry;
		int found = 0;
		list_for_each_entry(db_entry, &mospf_db, list) {
			if(db_entry->rid == instance->router_id) {
				for(int i = 0; i < db_entry->nadv; i++) {
					if(db_entry->array[i].network == network && 
					   db_entry->array[i].mask == iface->mask) {
						found = 1;
						break;
					}
				}
				break;
			}	
		}
        if(found) add_rt_entry(entry); 	
	}

    // 计算LSDB中的路由器数量
    int n_nodes = 0;
    mospf_db_entry_t *db_entry;
    list_for_each_entry(db_entry, &mospf_db, list) {
        n_nodes++;
    }

    if (n_nodes <= 1) {
        return;
    }

    // 创建路由器ID数组
    u32 *router_ids = malloc(n_nodes * sizeof(u32));
    if (!router_ids) {
        return;
    }

    // 记录所有路由器ID
    int i = 0;
    list_for_each_entry(db_entry, &mospf_db, list) {
        router_ids[i] = db_entry->rid;
        i++;
    }

    // 创建邻接矩阵
    int **graph = malloc(n_nodes * sizeof(int *));
    if (!graph) {
        free(router_ids);
        return;
    }

    for (i = 0; i < n_nodes; i++) {
        graph[i] = malloc(n_nodes * sizeof(int));
        if (!graph[i]) {
            for (int j = 0; j < i; j++) {
                free(graph[j]);
            }
            free(graph);
            free(router_ids);
            return;
        }
        memset(graph[i], 0, n_nodes * sizeof(int));
    }
    
    // 建立连接关系
    list_for_each_entry(db_entry, &mospf_db, list) {
        int src_idx = -1;
        for (i = 0; i < n_nodes; i++) {
            if (router_ids[i] == db_entry->rid) {
                src_idx = i;
                break;
            }
        }
        
        if (src_idx == -1) continue;
        
        for (i = 0; i < db_entry->nadv; i++) {
            struct mospf_lsa *lsa = &db_entry->array[i];
            
            if (lsa->rid != 0) {
                int dst_idx = -1;
                for (int j = 0; j < n_nodes; j++) {
                    if (router_ids[j] == lsa->rid) {
                        dst_idx = j;
                        break;
                    }
                }
                
                if (dst_idx != -1) {
                    graph[src_idx][dst_idx] = 1;
                    log(DEBUG, "Added link: router %u -> router %u", 
                        db_entry->rid, lsa->rid);
                }
            }
        }
    }
    
    // 找到自己在数组中的索引
    int self_idx = -1;
    for (i = 0; i < n_nodes; i++) {
        if (router_ids[i] == instance->router_id) {
            self_idx = i;
            break;
        }
    }
    
    if (self_idx == -1) {
        // 清理资源
        for (i = 0; i < n_nodes; i++) {
            free(graph[i]);
        }
        free(graph);
        free(router_ids);
        return;
    }
    
    // Dijkstra算法
    int *dist = malloc(n_nodes * sizeof(int));
    int *prev = malloc(n_nodes * sizeof(int));
    int *visited = malloc(n_nodes * sizeof(int));
    
    if (!dist || !prev || !visited) {
        if (dist) free(dist);
        if (prev) free(prev);
        if (visited) free(visited);
        for (i = 0; i < n_nodes; i++) {
            free(graph[i]);
        }
        free(graph);
        free(router_ids);
        return;
    }
    
    // 初始化
    for (i = 0; i < n_nodes; i++) {
        dist[i] = INT_MAX;
        prev[i] = -1;
        visited[i] = 0;
    }
    dist[self_idx] = 0;
    
    // Dijkstra主循环
    for (int count = 0; count < n_nodes; count++) {
        int min_dist = INT_MAX, u = -1;
        for (i = 0; i < n_nodes; i++) {
            if (!visited[i] && dist[i] < min_dist) {
                min_dist = dist[i];
                u = i;
            }
        }
        
        if (u == -1 || dist[u] == INT_MAX) break;
        
        visited[u] = 1;
        
        // 更新邻居距离
        for (i = 0; i < n_nodes; i++) {
            if (!visited[i] && graph[u][i] && 
                dist[u] != INT_MAX && 
                dist[u] + 1 < dist[i]) {
                dist[i] = dist[u] + 1;
                prev[i] = u;
            }
        }
    }

    // 构建路由表
    for (i = 0; i < n_nodes; i++) {
        if (i == self_idx || dist[i] == INT_MAX) continue;
        
        // 找到第一跳节点
        int next = i;
        while (prev[next] != self_idx && prev[next] != -1) {
            next = prev[next];
        }
        
        if (prev[next] != self_idx) continue;
        
        // 修复：找到前往next的接口和正确的网关
        u32 next_rid = router_ids[next];
        u32 gateway = 0;
        iface_info_t *out_iface = NULL;
        
        list_for_each_entry(iface, &instance->iface_list, list) {
            mospf_nbr_t *nbr;
            list_for_each_entry(nbr, &iface->nbr_list, list) {
                if (nbr->nbr_id == next_rid) {
                    gateway = nbr->nbr_ip;  // 修复：使用邻居的IP地址而不是掩码
                    out_iface = iface;
                    log(DEBUG, "Found gateway for router %u: "IP_FMT" via %s", 
                        next_rid, HOST_IP_FMT_STR(gateway), iface->name);
                    break;
                }
            }
            if (gateway) break;
        }
        
        if (!gateway || !out_iface) {
            log(DEBUG, "No gateway found for router %u", next_rid);
            continue;
        }
        
        // 添加目标路由器的网络到路由表
        mospf_db_entry_t *target;
        list_for_each_entry(target, &mospf_db, list) {
            if (target->rid == router_ids[i]) {
                for (int j = 0; j < target->nadv; j++) {
                    // 只添加直连网络（rid == 0）且不是本地直连的网络
                    if (target->array[j].rid == 0 && target->array[j].mask != 0) {
                        u32 network = target->array[j].network;
                        u32 mask = target->array[j].mask;
                        
                        // 检查是否已经是本地直连网络
                        int is_local = 0;
                        iface_info_t *check_iface;
                        list_for_each_entry(check_iface, &instance->iface_list, list) {
                            if ((check_iface->ip & check_iface->mask) == network) {
                                is_local = 1;
                                break;
                            }
                        }
                        
                        if (!is_local) {    
							int existed = 0;                        
							rt_entry_t *pos;
							list_for_each_entry(pos, &rtable, list) {
								if (pos->dest == network && pos->mask == mask) {
									// 如果已经存在相同的路由，则更新网关和接口
									pos->gw = gateway;
									pos->iface = out_iface;
									existed = 1;
									break;
								}
							}
							if(!existed){
								rt_entry_t *entry = new_rt_entry(network, mask, gateway, out_iface);
								add_rt_entry(entry);	
							}
                        }
                    }
                }
                break;
            }
        }
    }

    // 释放资源
    free(visited);
    free(prev);
    free(dist);
    for (i = 0; i < n_nodes; i++) {
        free(graph[i]);
    }
    free(graph);
    free(router_ids);
    
    log(INFO, "routing table calculation completed");
    print_rtable();
}