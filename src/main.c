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
#define BUFLEN 1024
const char MAGIC[3] = {0x03, 0x10, 0};

void exit_func(ctx *exit_ctx);

int main(){
    // define variables
    int proc_fd; // process file descriptor
    char *buf;
    char temp_buf[BUFLEN];
    ctx ctx;

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

    while ((c = fgetc(priv_fp)) != EOF){ // get user private key
        ctx.priv_key[i] = c;
        i++;
    }
    ctx.priv_key[i] = 0;
    i = 0;
    while((c = fgetc(pub_fp)) != EOF){
        ctx.pub_key[i] = c;
        i++;
    }
    ctx.pub_key[i] = 0;
    i = 0;

    // init threads

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
    bzero(buf, BUFLEN);
    bzero(temp_buf, BUFLEN);

    msg raw_msg, out_msg;
    int res = 0;
    int buf_sz = 0;
    i = 1;

    raw_msg.cipher = malloc(4096/8); // allocate memory for msg ciphers
    out_msg.cipher = malloc(4096/8);
    // main loop, process data from proc_fd and handle program execution, send messages
    while (1){
        while ((res = read(ctx.ui_sock, buf + ((i-1) * BUFLEN), BUFLEN))){
            buf = realloc(buf, BUFLEN*(i+1));
            printf("%s\n", buf);
            for (int k = 0; k < BUFLEN; k++){
                if (buf[k+BUFLEN*(i-1)] == '\n'){
                    res = 1;
                    break;
                }
                buf_sz++;
            }
            i++;
            if (res==1)
                break;
            else
                continue;
        }
        if (buf_sz > (2 * strlen(MAGIC) + 4)){
            if (strstr(&(buf[0]), MAGIC) == strstr(&(buf[buf_sz-3]), MAGIC) == 0){
                // parse buffer
                int m = 3;
                raw_msg.type = buf[m] - '0';
                m+=2;

                if (raw_msg.type == MESSAGE){
                    // store message details from client input socket
                    printf("Message\n");
                    raw_msg.recv_pub_key = realloc(raw_msg.recv_pub_key, strlen(&(buf[m])));
                    printf("pubkey-malloc\n");
                    strcpy(raw_msg.recv_pub_key, &(buf[m]));
                    printf("pubkey-copy\n");
                    m += strlen(raw_msg.recv_pub_key) + 1;
                    raw_msg.timestamp = realloc(raw_msg.timestamp, strlen(&(buf[m])));
                    printf("timestamp-malloc\n");
                    strcpy(raw_msg.timestamp, &(buf[m]));
                    printf("timestamp-copy\n");
                    m += strlen(raw_msg.timestamp) + 1;
                    strncpy(raw_msg.sz, &(buf[m]), 4);
                    printf("rawmsg_sz\n");
                    m += 4 + 1;
                    raw_msg.content = realloc(raw_msg.content, strlen(&(buf[m])));
                    strcpy(raw_msg.content, &(buf[m]));

                    raw_msg.send_pub_key = realloc(raw_msg.send_pub_key, strlen(ctx.pub_key));
                    out_msg.recv_pub_key = realloc(out_msg.recv_pub_key, strlen(raw_msg.recv_pub_key));
                    out_msg.send_pub_key = realloc(out_msg.send_pub_key, strlen(raw_msg.send_pub_key));

                    strcpy(raw_msg.send_pub_key, ctx.pub_key);
                    strcpy(out_msg.recv_pub_key, raw_msg.recv_pub_key);
                    strcpy(out_msg.send_pub_key, raw_msg.send_pub_key);
                    // Encrypt certificate key (RSA)
                    printf("waypoint-1\n");

                    int cipher_sz;
                    // move this to certificate code
                    if ((cipher_sz = private_encrypt(raw_msg.content, atoi(raw_msg.sz)+1, ctx.priv_key, raw_msg.cipher)) == -1){ // encrypt message
                        printf("message encryption error\n");
                    }
                    printf("waypoint-1.25\n");
                    out_msg.sz[4] = 0;
                    for (int k = 3; k >= 0; k--){
                        out_msg.sz[k] = (cipher_sz % 10) + '0';
                        cipher_sz /= 10;
                    }
                    printf("waypoint-1.5\n");
                    int out_msg_sz = atoi(out_msg.sz);
                    for (int k = 0; k < out_msg_sz; k++){ // store cipher in out_msg
                        m = k;
                        out_msg.cipher[k] = raw_msg.cipher[k] + '0';
                    }
                    out_msg.cipher[++m] = 0;

                    printf("waypoint-2\n");

                    unsigned char *temp = malloc(strlen(raw_msg.content) + strlen(raw_msg.send_pub_key) + 1);
                    strcpy(temp, raw_msg.content);
                    strcat(temp, raw_msg.send_pub_key);

                    unsigned char **temp_checksum = sha256(temp, (size_t)raw_msg.sz, NULL);

                    for (int k = 0; k < 32; k++){
                        out_msg.checksum[i] = *temp_checksum[i] + '0';
                    }
                    out_msg.checksum[32] = 0;

                    strcpy(out_msg.timestamp, raw_msg.timestamp);

                    send_msg(out_msg, ctx.server_fd);

                    memset(&raw_msg, 0, sizeof(raw_msg));
                    memset(&out_msg, 0, sizeof(out_msg));
                }
                if(raw_msg.type == CON){
                    printf("Connect\n");
                    char addr[256] = {0};
                    char port_s[5] = {0};
                    int port;
                    strncpy(addr,&(buf[m]), 256);
                    m += strlen(addr);
                    strncpy(port_s, &(buf[m]), 5);
                    m += 5;
                    port = atoi(port_s);

                    if ((ctx.server_fd = server_connect(addr, port)) < 0){
                        printf("server connection error!\n");
                    }
                }

            }
        }
        bzero(&(buf[0]), (BUFLEN*i));
        i = 1;
        buf = &(buf[0]);
        buf_sz = 0;
    }
}

void exit_func(ctx *exit_ctx){
    shutdown(exit_ctx->ui_sock, SHUT_RDWR);
    shutdown(exit_ctx->server_fd, SHUT_RDWR);
    close(exit_ctx->ui_sock);
    close(exit_ctx->server_fd);
}