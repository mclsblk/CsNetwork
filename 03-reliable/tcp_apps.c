#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>

// tcp server application, listens to port (specified by arg) and serves only one
// connection request

#define MAX_TRANS 1024

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

	// 打开文件用于保存接收到的数据
	FILE *file = fopen("server-output.dat", "wb");
	if (!file) {
		log(ERROR, "Failed to open file for writing.");
		//tcp_sock_close(csk);
		//return NULL;
	}

	int max_recv = csk->rcv_buf->size;
	while (1) {
		sleep_on(csk->wait_recv);

		
		int recv_len = ring_buffer_used(csk->rcv_buf);
		char recv_buf[recv_len];
		
		if (recv_len > 0) {
			// 将接收到的数据写入文件
            // 接收数据
			read_ring_buffer(csk->rcv_buf, recv_buf, recv_len);
			fwrite(recv_buf, 1, recv_len, file);
			log(DEBUG, "server received %d bytes of data", recv_len);
			//log(DEBUG, "%s", recv_buf);
		}

		if(csk->state == TCP_CLOSE_WAIT) {
			log(DEBUG, "client closed the connection.");
			break;
		}		
	}

	sleep(10);

	tcp_sock_close(csk);
	tcp_sock_close(tsk);

	fclose(file);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	// 打开文件以读取数据
    FILE *file = fopen("client-input.dat", "rb");
	FILE *fi = fopen("check-input.dat", "wb");
    if (!file) {
        log(ERROR, "Failed to open file for reading.");
        tcp_sock_close(tsk);
        return NULL;
    }

	fseek(file, 0, SEEK_END);
	long file_size = ftell(file);
	long sent = 0;
	rewind(file);

	char send_buf[file_size];
	fread(send_buf, 1, file_size, file);
	fwrite(send_buf, 1, file_size, fi);
	fclose(fi);
	fclose(file);

	log(DEBUG, "client read %ld bytes from file.", file_size);
	tcp_sock_write(tsk, send_buf, file_size);

	sleep(5);

	tcp_sock_close(tsk);

	return NULL;
}
