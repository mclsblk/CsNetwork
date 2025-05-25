#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <string.h>

int main(void){
    unsigned int ip_int;
    unsigned int a, b, c, d; 
    in_addr_t ip_addr;
    // char *p = "192.168.120.30";
    // printf("ip: %s\n", p);

    // in_addr_t ip_addr = inet_addr(p);
    // printf("inet_addr result: %u\n", ip_addr);
    // unsigned int r = ntohl(ip_addr);
    // printf("r: %u\n", r);

    // if (sscanf(p, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
    //     printf("Parsed: %u.%u.%u.%u\n", a, b, c, d);
    //     // 转换为32位整数 (主机字节序)
    //     ip_int = (a << 24) | (b << 16) | (c << 8) | d;
    //     printf("32-bit integer: %u\n", ip_int);
    // }

    // printf("从高位到低位:\n");
    // for (int i = 31; i >= 0; i--) {
    //     int bit = (ip_int >> i) & 1;
    //     printf("%d", bit);
    // }
    // printf("\n");

    FILE* fp = fopen("./forwarding_table.txt", "r");
    if(fp == NULL){
        fprintf(stderr,"Error: %s\n",__func__);
    }

    char split[20];
    fgets(split, sizeof(split), fp);

    char *ip = strtok(split, " ");
    char *p_mask = strtok(NULL, " ");
    char *p_port = strtok(NULL, " ");
    ip_addr = inet_addr(ip);
    ip_int = ntohl(ip_addr);
    int mask = atoi(p_mask);
    int port = atoi(p_port);
    printf("ip: %s, mask: %d, port: %d\n", ip, mask, port);
    for (int j = 0; j < 10; j += 2) {
        int p = 30 - j;
        int index = (ip_int >> p) & 0x3;
        int odd_index = ((ip_int >> (p + 1)) & 0x1) + 4;  // 奇数位索引
        int try_odd = (index & 0x2) + 4;
        printf("index: %d odd:%d %d\n", index, odd_index, try_odd);
        printf("%d %d %d\n", 5, (5 >> 1) & 0x3, (5 >> 2) & 0x1);
    }
}