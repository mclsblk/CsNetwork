#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "pthread.h"

void handle_https_request(SSL* ssl){
    const char* response_template = 
        "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n"; 
    char response[256];
    int status_code;
    long  content_length = 0;
    char* status_str;

    if (SSL_accept(ssl) == -1){
		perror("SSL_accept failed");
		exit(1);
	}
    else {
		char buf[2048] = {0};
        char *file_buf;
        int is_filebuf_empty = 1;

        int bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes < 0) {
			perror("SSL_read failed");
			exit(1);
		}
        
        char buf_cp[2048];
        strcpy(buf_cp, buf);
        char *start = strstr(buf_cp, "GET");
        char *file_path = strtok(start + 4, " ");

        if(file_path == NULL){
            status_code = 400;
            status_str = "Bad Request";
            content_length = 0;
        }
        else{
            if(file_path[0]=='/') file_path++;

            FILE *fp = fopen(file_path, "rb");
            if(!fp){
                status_code = 404;
                status_str = "Not Found";
                content_length = 0;
            }
            else{
                status_code = 200;
                status_str = "OK";

                fseek(fp, 0, SEEK_END);
                long f_size = ftell(fp);
                rewind(fp);

                file_buf = (char *)malloc(f_size + 1);
                fread(file_buf, 1, f_size, fp);
                fclose(fp);
                file_buf[f_size] = '\0';
                is_filebuf_empty = 0;
            
            
                long r_start = 0, r_end = f_size - 1;

                char *range_info = strstr(buf, "Range");
                if(range_info){
                    status_code = 206;
                    status_str = "Partial Content";
                    sscanf(range_info, "Range: bytes=%ld-%ld", &r_start, &r_end);
                    file_buf += r_start;                    
                }
                content_length = r_end - r_start + 1;
            }
        }

        snprintf(response, sizeof(response), 
            response_template, status_code, status_str, content_length);
        SSL_write(ssl, response, strlen(response));
        if(is_filebuf_empty == 0){
            SSL_write(ssl, file_buf, content_length);
        }
    }   

    int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
}

void handle_http_request(int *arg){
    char *response_template = "HTTP/1.0 301 Moved Permenantly\r\nLocation: %s\r\n\r\n";
    char buf[2048] = {0};
    int sockfd = *arg;
    recv(sockfd, buf, 2048, 0);
    
    char *start = strstr(buf, "GET");
    char *file_path = strtok(start + 4, " ");
    char re_file_head[128] = "https://10.0.0.1";
    strcat(re_file_head, file_path);
    char *re_file_path = re_file_head;
    char response[256];
    snprintf(response, sizeof(response), response_template, re_file_path);
    send(sockfd, response, strlen(response),0);

    close(sockfd);
}

void* handle_https_port(void *args){
    // init SSL Library
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	// enable TLS method
	const SSL_METHOD *method = TLS_server_method();

	// 创建SSL_CTX  
    SSL_CTX *ctx = SSL_CTX_new(method); 

    // 载入证书和私钥  
    if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0 ||  
        SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0){  
        perror("load cert or prikey failed");  
        exit(1);  
    }  

    int port = 443;
    
	// init socket, listening to port
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);

	while (1) {
		struct sockaddr_in caddr;
		socklen_t len = sizeof(caddr);
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
        SSL *ssl = SSL_new(ctx); 
        SSL_set_fd(ssl, csock);
        handle_https_request(ssl); 
    }

	close(sock);
	SSL_CTX_free(ctx);

}

void* handle_http_port(void *args){
    int port = 80;
    
	// init socket, listening to port
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);

	while (1) {
		struct sockaddr_in caddr;
		socklen_t len = sizeof(caddr);
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
        handle_http_request(&csock); 
    }

	close(sock);
}

int main(){
	

    // 创建线程  
    pthread_t tid1, tid2;  
    if (pthread_create(&tid1, NULL, handle_https_port, NULL) != 0 ||  
        pthread_create(&tid2, NULL, handle_http_port, NULL) != 0) {  
        perror("pthread_create failed");  
        exit(1);  
    }  

    // 等待线程结束  
    pthread_join(tid1, NULL);  
    pthread_join(tid2, NULL);  

	return 0;
}
