#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));
	log(DEBUG, "tcp sock state: %s", tcp_state_str[tsk->state]);
	
	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	while (1) {
		sleep_on(csk->wait_recv);
		if(csk->state == TCP_CLOSE_WAIT) {
			log(DEBUG, "client closed the connection.");
			break;
		}

		int max_recv = csk->rcv_wnd;
		char *echo = "server echoes: ";
		int echo_len = strlen(echo);
		int max_send = echo_len + max_recv;

		char recv_buf[max_recv], buf[max_send];
		// 接收数据
		int recv_len = tcp_sock_read(csk, recv_buf, max_recv);
		if (recv_len > 0) {
			// 确保是以null结尾的字符串
			if(recv_buf[recv_len -1] != '\0') recv_buf[recv_len] = '\0'; 

			//log(DEBUG, "server received %d bytes of data", recv_len);
			log(DEBUG, "%s", recv_buf);
		}
		else
			continue;
		
		// 发送响应数据
		sprintf(buf, "%s%s", echo, recv_buf);
		int send_len = strlen(buf);
		int len = tcp_sock_write(csk, buf, send_len);
		log(DEBUG, "server send %d bytes of data", len);
	}
	

	sleep(5);

	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	char data[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int datalen = sizeof(data) - 1;
	char *rotated_data = (char *)malloc(datalen + 1);


	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

    for (int i = 0; i < 10; i++) {
        int j;
        // 复制 data[i:] 部分
        for (j = 0; j < datalen - i; j++) {
            rotated_data[j] = data[i + j];
        }
        // 复制 data[:i] 部分
        for (int k = 0; k < i; k++) {
            rotated_data[j + k] = data[k];
        }
        rotated_data[datalen + 1] = '\0';  // 添加字符串结束符
        
        // 发送旋转后的数据
        tcp_sock_write(tsk, rotated_data, datalen);
        //log(DEBUG, "client send %d bytes of data (rotation %d)", datalen, i);

        sleep_on(tsk->wait_recv);

		// 接收响应数据
		char recv_buf[1001];  // 假设最大接收1000字节
		int recv_len = tcp_sock_read(tsk, recv_buf, 1000);
		if (recv_len > 0) {
			if(recv_buf[recv_len -1] != '\0') recv_buf[recv_len] = '\0'; 
			//log(DEBUG, "client received %d bytes of data", recv_len);
			printf("%s\n", recv_buf);
		}
		
		// 等待1秒
		sleep(1);
    }
	sleep(1);

	tcp_sock_close(tsk);

	return NULL;
}
