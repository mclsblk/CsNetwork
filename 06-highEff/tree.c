#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <arpa/inet.h>

// 前缀树节点结构
struct TrieNode {
    struct TrieNode* children[6];  // 存储子节点
    int port;                  // 存储端口号
    int isEnd;               // 标记是否为结尾
};

struct RootOfALL
{
    struct TrieNode* root[255]; // 存储根节点
};

// 线程参数结构体
typedef struct {
    uint32_t* ip_vec;       // 输入IP数组
    uint32_t* results;      // 结果数组
    int start_idx;          // 起始索引
    int end_idx;            // 结束索引
} thread_arg_t;

struct TrieNode* root; // 根节点
struct TrieNode* advance_root; // 高级树根节点
struct RootOfALL* rfroot;


static const int shifts[12] = {
    22, 20, 18, 16, 14, 12, 10, 8,
    6, 4, 2, 0 };

struct TrieNode* allocNode(int port){

    struct TrieNode* newNode = (struct TrieNode*)malloc(sizeof(struct TrieNode));

    newNode->port = port;
    newNode->isEnd = 0;

    for (int i = 0; i < 6; i++) {
        newNode->children[i] = NULL;
    }
    //printf("alloc\n");
    return newNode;
}

static inline int get_index(uint32_t ip, int position) {
    return (ip >> position) & 0x3;
}

static inline int get_odd_index(uint32_t ip, int position) {
    return ((ip >> (position+1)) & 0x1) + 4;
}

// return an array of ip represented by an unsigned integer, size is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file){
    uint32_t* res = (uint32_t*)malloc(TEST_SIZE * sizeof(uint32_t));

    FILE* fp = fopen(lookup_file, "r");
    if(fp == NULL){
        fprintf(stderr,"Error: %s\n",__func__);
        return NULL;
    }

    char ip[20];

    int i = 0;
    while (i < TEST_SIZE && fgets(ip, sizeof(ip), fp) != NULL) {
        
        ip[strcspn(ip, "\n")] = '\0';      
        // Convert the IP address string to a 32-bit integer
        in_addr_t ip_addr = inet_addr(ip);
        if (ip_addr == INADDR_NONE) {
            fprintf(stderr, "Invalid IP address: %s\n", ip);
            continue;
        }
        // Store the IP address in the array
        res[i] = ntohl(ip_addr);
        i++;
    }
    fclose(fp);
    return res;
}

// Constructing an advanced trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file){

    root = allocNode(0);
    //printf("1");
    FILE* fp = fopen(forward_file, "r");
    if(fp == NULL){
        fprintf(stderr,"Error: %s\n",__func__);
        return;
    }

    char split[30];

    while(fgets(split, sizeof(split), fp) != NULL){
        //printf(split);
        // Remove newline character
        split[strcspn(split, "\n")] = '\0';

        char *ip = strtok(split, " ");
        char *p_mask = strtok(NULL, " ");
        char *p_port = strtok(NULL, " ");
        in_addr_t ip_addr = inet_addr(ip);
        unsigned int ip_int = ntohl(ip_addr);
        int mask = atoi(p_mask);
        int port = atoi(p_port);
        //printf("ip:%u\n", ip_int);
        // Create a new TrieNode
        struct TrieNode* current = root;
        for (int i = 0; i < mask; i++) {
            int index = (ip_int >> (31 - i)) & 1;
            if (current->children[index] == NULL) {
                current->children[index] = allocNode(0);
            }
            current = current->children[index];
        }

        current->port = port; // Store the port number
        current->isEnd = 1; // Mark the end of the IP address
    }

    // Close the file
    fclose(fp);
}

// Look up the ports of ip in file `lookup_file` using the basic tree
uint32_t *lookup_tree(uint32_t* ip_vec){
    uint32_t* res = (uint32_t*)malloc(TEST_SIZE * sizeof(uint32_t));
    uint32_t* temp_buffer = (uint32_t*)malloc(TEST_SIZE * sizeof(uint32_t));
    for(int i = 0; i < TEST_SIZE; i++){
        temp_buffer[i] = -1;
    }

    for(int i = 0; i < TEST_SIZE; i++){
        res[i] = -1;
        struct TrieNode* current = root;
        uint32_t ip = ip_vec[i];
        uint32_t tmp = -1;

        for (int j = 0; j < 32; j++) {
            int index = (ip >> (31 - j)) & 0x1;
            if (current->children[index] == NULL) break;
            else current = current->children[index];

            if (current->isEnd == 1 && current->port != -1)
                tmp = current->port;
        }

        if (current == root) res[i] = -1;
        temp_buffer[i] = tmp;
    }

    for(int i = 0; i < TEST_SIZE; i++){
        res[i] = temp_buffer[i];
    }
    free(temp_buffer);

    return res;
}

// Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
void create_tree_advance(const char* forward_file){
    rfroot = (struct RootOfALL*)malloc(sizeof(struct RootOfALL));
    for(int i = 0; i < 255; i++) {
        rfroot->root[i] = allocNode(0);
    }

    FILE* fp = fopen(forward_file, "r");

    char split[30];
    struct TrieNode* current;
    while(fgets(split, sizeof(split), fp) != NULL){
        char *ip = strtok(split, " ");
        char *p_mask = strtok(NULL, " ");
        char *p_port = strtok(NULL, " ");
        in_addr_t ip_addr = inet_addr(ip);
        unsigned int ip_int = ntohl(ip_addr);
        int mask = atoi(p_mask);
        int port = atoi(p_port);

        int prefix = (ip_int >> 24) & 0xFF; // Get the prefix
        advance_root = rfroot->root[prefix]; // Get the root node for the prefix
        if(mask == 8){
            advance_root->port = port;
            advance_root->isEnd = 1; // Mark the end of the IP address
            continue;
        }
        
        // Create a new TrieNode
        current = advance_root;
        for (int i = 8; i < mask; i+=2) {
            int index = (ip_int >> (30 - i)) & 0x3;
            if (current->children[index] == NULL) {
                if(i == mask - 1){
                    int odd_index = ((ip_int >> (31 - i)) & 0x1) + 4;
                    current->children[odd_index] = allocNode(0);
                    current = current->children[odd_index];
                    break;
                }
                else 
                    current->children[index] = allocNode(0);
            }
            current = current->children[index];
        }
        current->isEnd = 1; // Mark the end of the IP address
        current->port = port; // Store the port number
    }
    fclose(fp);
}

#pragma GCC optimize("unroll-loops")
#pragma GCC optimize("O3")


uint32_t lookup_single_ip(uint32_t ip){
    struct TrieNode* current;

    int prefix = (ip >> 24) & 0xFF; // Get the prefix
    advance_root = rfroot->root[prefix]; // Get the root node for the prefix        
    
    int tmp = -1;
    int index, odd_index;
    
    if(advance_root->isEnd == 1) tmp = advance_root->port;
    
    current = advance_root;
    for (int j = 0; j < 12; j++) {

        index = get_index(ip, shifts[j]); // 获取当前索引
        odd_index = get_odd_index(ip, shifts[j]); // 获取奇数索引

        if (current->children[odd_index] != NULL)
            tmp = current->children[odd_index]->port;

        if (current->children[index] == NULL) break;
        else current = current->children[index];
        if (current->isEnd == 1) tmp = current->port;
        
    }
    return tmp;
}

// 线程工作函数
void* thread_worker(void* arg) {
    thread_arg_t* t_arg = (thread_arg_t*)arg;
    
    // 处理分配给此线程的IP范围
    for(int i = t_arg->start_idx; i < t_arg->end_idx; i++) {
        t_arg->results[i] = lookup_single_ip(t_arg->ip_vec[i]);
    }
    
    pthread_exit(NULL);
}

// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance(uint32_t* ip_vec){
    uint32_t* res = (uint32_t*)malloc(TEST_SIZE * sizeof(uint32_t));

    const int NUM_THREADS = 4;

    pthread_t threads[NUM_THREADS];
    thread_arg_t thread_args[NUM_THREADS];
    
    // 计算每个线程处理的IP数量
    int chunk_size = (TEST_SIZE + NUM_THREADS - 1) / NUM_THREADS;
    
    // 创建线程并分配工作
    for(int t = 0; t < NUM_THREADS; t++) {
        thread_args[t].ip_vec = ip_vec;
        thread_args[t].results = res;
        thread_args[t].start_idx = t * chunk_size;
        thread_args[t].end_idx = (t + 1) * chunk_size;
        
        // 确保最后一个线程不会越界
        if(thread_args[t].end_idx > TEST_SIZE) {
            thread_args[t].end_idx = TEST_SIZE;
        }
        
        // 创建线程
        int rc = pthread_create(&threads[t], NULL, thread_worker, &thread_args[t]);
        if(rc) {
            printf("ERROR: pthread_create() returned %d\n", rc);
            exit(-1);
        }
    }
    
    // 等待所有线程完成
    for(int t = 0; t < NUM_THREADS; t++) {
        pthread_join(threads[t], NULL);
    }
    

    return res;
}
