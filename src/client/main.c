#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<pthread.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<sys/un.h>
#include"common.h"

#define PROC_SOCK "/tmp/carbide-client.sock"

const char MAGIC[2] = {0x69, 0x69};

void exit_func(ctx *exit_ctx);

int main(){
    // define variables

    pthread_t recv_thread; // recieving thread
    int proc_fd; // process file descriptor
    char *buf; // main input buffer
    char *buf_start; // starting pointer of buffer mem
    int res = 0;
    char temp_buf[BUFLEN];
    ctx ctx;

    memset(&ctx, 0, sizeof(ctx)); // initialize ctx to 0

    atexit((void*)&exit_func); // handle program exit

    //
    FILE *priv_fp = open_file("privatekey");
    FILE *pub_fp = open_file("publickey");
    
    if (priv_fp == NULL){
        printf("Private keyfile not found\n");
        return -1;
    }
    if (pub_fp == NULL){
        printf("Public keyfile not found\n");
        return -1;
    }

    char c;
    int i = 0;

    // Load public and private key into buffers

    int priv_key_sz = fsize(priv_fp);
    int pub_key_sz = fsize(pub_fp);

    ctx.priv_key = malloc(priv_key_sz+2);
    ctx.pub_key = malloc(pub_key_sz+2);

    while ((c = fgetc(priv_fp)) != EOF && (i < priv_key_sz)){ // get user private key
        ctx.priv_key[i] = c;
        i++;
    }
    ctx.priv_key[i] = '\0';
    i = 0;
    while((c = fgetc(pub_fp)) != EOF && (i < pub_key_sz)){
        ctx.pub_key[i] = c;
        i++;
    }
    ctx.pub_key[i] = '\0';
    i = 0;

    fclose(priv_fp);
    fclose(pub_fp);

    ctx.addr = sha256(ctx.pub_key, strlen(ctx.pub_key), NULL);

    if ((res = pthread_create(&recv_thread, NULL, recv_msg, (void*)&ctx)) != 0){ // create recieving thread
        printf("failed to initialize recv_thread");
    }

    if ((proc_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){ // create socket to allow communication between UI and client process
        perror("proc_fd socket");
    }
    int true = 1;
    setsockopt(proc_fd, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(int)); // re-use proc_fd socket
    remove(PROC_SOCK);

    struct sockaddr_un proc_addr;
    memset ((char*)&proc_addr, 0, sizeof(proc_addr));
    proc_addr.sun_family = AF_UNIX;
    strncpy(proc_addr.sun_path, PROC_SOCK, strlen(PROC_SOCK));

    if (bind(proc_fd, (struct sockaddr*)&proc_addr, sizeof(struct sockaddr_un)) == -1){
        perror("proc_fd bind");
    }

    if (listen(proc_fd, 1) == -1){
        perror("proc_fd listen");
    }

    struct sockaddr_un ui;
    int ui_len = sizeof(ui);

    ctx.ui_sock = accept(proc_fd, (struct sockaddr*)&ui, &ui_len);

    buf = malloc(BUFLEN*sizeof(char));
    buf_start = buf;
    bzero(buf, BUFLEN);
    bzero(temp_buf, BUFLEN);

    msg raw_msg;

    raw_msg.recv_addr = malloc(SHA256_SZ + 1);
    raw_msg.send_addr = ctx.addr;

    int buf_sz = 1;
    int buf_len = 0;
    i = 1; 
    // main loop, process data from proc_fd and handle program execution, send messages
    while (1){
        while ((res = read(ctx.ui_sock, buf + ((i-1) * BUFLEN), BUFLEN))){
            buf_len += res;
            buf = buf_start;
            if (buf_len == BUFLEN){
                buf = realloc(buf, BUFLEN*(i+1));
                buf_start = buf;
                buf_sz++;
                i++;
            } else {
                if (memcmp(buf + buf_len - sizeof(MAGIC) - 1, MAGIC, sizeof(MAGIC)) == 0){
                    break;
                } else{
                    continue;
                }
            }

        }    
        if (buf_len > (2 * sizeof(MAGIC) + 4)){
                // parse buffer
                int m = 2;
                raw_msg.type = buf[m];
                m+=1;

                if (raw_msg.type == MESSAGE){
                    // store message details from client input socket
                    const int cipher_sz = rsa_sz(ctx.pub_key, PUBLIC); // maximum length of RSA cipher (CA)
                    int cipher_len;
                    int content_len;

                    raw_msg.cipher = calloc(cipher_sz+1, 1); // hex representation of message cipher
                    //raw_msg.cipher = NULL;
                    unsigned char *temp_cipher = malloc(cipher_sz + 1);
                    raw_msg.content = malloc(KEY_SZ/8+1);

                    memcpy(raw_msg.recv_addr, &(buf[m]), SHA256_SZ);
    
                    m += SHA256_SZ;

                    raw_msg.timestamp = *(unsigned int*)(&buf[m]);
                    m += sizeof(raw_msg.timestamp);
                    
                    content_len = *(unsigned int*)(&buf[m]);
                    m += sizeof(content_len);

                    if ((content_len + SHA256_SZ) > KEY_SZ/8){
                        printf("Certificate contents too large!\n");
                        return -1;
                    }
                    memcpy(raw_msg.content, &(buf[m]), content_len);
                    raw_msg.content[content_len] = 0;
                    // Encrypt certificate key (RSA)        
                    unsigned char *temp = malloc(content_len + SHA256_SZ + 1);
                    memcpy(temp, raw_msg.content, content_len);
                    memcpy(temp+content_len, raw_msg.send_addr, SHA256_SZ);

                    unsigned char *temp_checksum = sha256(temp, (size_t)(content_len + SHA256_SZ), NULL);
                    memcpy(&raw_msg.content[content_len], temp_checksum, SHA256_SZ);
                    content_len = content_len + SHA256_SZ;
                    
                    if ((cipher_len = public_encrypt(raw_msg.content, content_len, ctx.pub_key, raw_msg.cipher)) == -1){ // encrypt message
                        printf("message encryption error\n");
                    }
                    raw_msg.sz = cipher_len;
                    printf("sending message\n");
                    send_msg(raw_msg, ctx.server_fd);
                    free(raw_msg.cipher);
                    free(raw_msg.content);
                } else if(raw_msg.type == CON){
                    printf("Connect\n");
                    char addr[256] = {0};
                    if (strchr(&buf[m], 0) == NULL){
                        printf("Improperly formatted IPv4 address!\n");
                    } else {
                        strncpy(addr, &(buf[m]), 256);
                        m += strlen(addr) + 1;
                        if ((ctx.server_fd = server_connect(addr, PORT, DEFAULT)) < 0){
                            printf("server connection error!\n");
                        }
                        ctx.stat.connected = 1;
                    }
                } else {
                    printf("Message format error\n");
                }
                raw_msg.type = 0;
                raw_msg.timestamp = 0;
                raw_msg.sz = 0;
                memset(raw_msg.checksum, 0, sizeof(raw_msg.checksum));
        }
        i = 1;
        free(buf);
        buf = malloc(BUFLEN);
        buf_start = buf;
        buf_sz = 1;
        buf_len = 0;
    }
}

void exit_func(ctx *exit_ctx){
    shutdown(exit_ctx->ui_sock, SHUT_RDWR);
    shutdown(exit_ctx->server_fd, SHUT_RDWR);
    close(exit_ctx->ui_sock);
    close(exit_ctx->server_fd);
}
