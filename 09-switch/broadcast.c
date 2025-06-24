#include "base.h"
#include <stdio.h>

// XXX ifaces are stored in instace->iface_list
extern ustack_t *instance;

extern void iface_send_packet(iface_info_t *iface, const char *packet, int len);

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	if (!iface || !packet || len <= 0) {
        return;
    }
    
    // 遍历所有接口
    iface_info_t *riface = NULL;
    list_for_each_entry(riface, &instance->iface_list, list) {
        // 跳过接收数据包的接口，避免回环
        if (riface == iface) {
            continue;
        }
        
        // 通过当前接口发送数据包
        iface_send_packet(riface, packet, len);
        
    }

}
