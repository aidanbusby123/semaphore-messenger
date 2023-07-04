#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<pthread.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<sys/un.h>
#include<openssl/sha.h>
#include"common.h"

#define PROC_SOCK "/tmp/carbide-client.sock"
#define BUFLEN 1024
const char MAGIC[3] = {0x03, 0x10, 0};

void exit_func(ctx *exit_ctx);

int main(){
    // define variables
    int proc_fd; // process file descriptor
    char *buf; // main input buffer
    char *buf_start; // starting pointer of buffer mem
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

    int priv_key_sz = fsize(priv_fp);
    int pub_key_sz = fsize(pub_fp);

    ctx.priv_key = malloc(priv_key_sz+1);
    ctx.pub_key = malloc(pub_key_sz+1);

    while ((c = fgetc(priv_fp)) != EOF && (i < priv_key_sz)){ // get user private key
        ctx.priv_key[i] = c;
        i++;
    }
    ctx.priv_key[i] = '\0';
    printf("%s\n", ctx.priv_key);
    i = 0;
    while((c = fgetc(pub_fp)) != EOF && (i < pub_key_sz)){
        ctx.pub_key[i] = c;
        i++;
    }
    ctx.pub_key[i] = '\0';
    printf("%s\n", ctx.pub_key);
    i = 0;

    fclose(priv_fp);
    fclose(pub_fp);

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
    buf_start = buf;
    bzero(buf, BUFLEN);
    bzero(temp_buf, BUFLEN);

    msg raw_msg;
    const int send_pub_key_len = strlen(ctx.pub_key);
    const int send_priv_key_len = strlen(ctx.priv_key);
    int recv_pub_key_len = 0;
    int res = 0;
    int buf_sz = 0;
    i = 1; 
    // main loop, process data from proc_fd and handle program execution, send messages
    while (1){
        while ((res = read(ctx.ui_sock, buf_start + ((i-1) * BUFLEN), BUFLEN))){
            buf = realloc(buf, BUFLEN*(i+1));
            buf_start = buf;
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
                // parse buffer
                int m = 3;
                raw_msg.type = buf[m] - '0';
                m+=2;

                if (raw_msg.type == MESSAGE){
                    // store message details from client input socket
                    const int cipher_sz = rsa_sz(ctx.pub_key, PUBLIC); // maximum length of RSA cipher (CA)
                    int cipher_len;
                    int content_len;

                    raw_msg.send_pub_key = malloc(send_pub_key_len+1);
                    raw_msg.recv_pub_key = NULL;

                    //raw_msg.cipher = calloc(2 * cipher_sz+1, 1); // hex representation of message cipher
                    raw_msg.cipher = NULL;
                    unsigned char *temp_cipher = malloc(cipher_sz + 1);
                    raw_msg.content = malloc(KEY_SZ/8+1);

                    strcpy(raw_msg.send_pub_key, ctx.pub_key);

                    //allocate mem for reciever pub key
                    recv_pub_key_len = strlen(&(buf[m]));
                    raw_msg.recv_pub_key = realloc(raw_msg.recv_pub_key, recv_pub_key_len+1);
                    strcpy(raw_msg.recv_pub_key, &(buf[m]));

                    m += recv_pub_key_len + 1;

                    strncpy(raw_msg.timestamp, &(buf[m]), sizeof(raw_msg.timestamp)-2);
                    raw_msg.timestamp[sizeof(raw_msg.timestamp)-1] = 0;
                    m += strlen(raw_msg.timestamp) + 1;
                    
                    strncpy(raw_msg.sz, &(buf[m]), 4);
                    m += strlen(raw_msg.sz) + 1;
                    
                    if ((strlen(&(buf[m]))+2*SHA256_DIGEST_LENGTH) > KEY_SZ/8){
                        printf("Certificate contents too large!\n");
                        return -1;
                    }
                    strcpy(raw_msg.content, &(buf[m]));
                    content_len = strlen(raw_msg.content);

                    strcpy(raw_msg.send_pub_key, ctx.pub_key);
                    // Encrypt certificate key (RSA)        
                    unsigned char *temp = malloc(content_len + send_pub_key_len + 1);
                    strcpy(temp, raw_msg.content);
                    strcat(temp, raw_msg.send_pub_key);

                    unsigned char *temp_checksum = sha256(temp, (size_t)(content_len+send_pub_key_len+1), NULL);
                    strcpy(raw_msg.checksum, temp_checksum);
                    strcat(raw_msg.content, raw_msg.checksum);

                    content_len = content_len + SHA256_DIGEST_LENGTH*2;

                    if ((cipher_len = public_encrypt(raw_msg.content, content_len, ctx.pub_key, temp_cipher)) == -1){ // encrypt message
                        printf("message encryption error\n");
                    }
                    raw_msg.cipher = char_to_hex(temp_cipher);
                    cipher_len *= 2;
                    for (int k = 3; k >= 0; k--){
                        raw_msg.sz[k] = cipher_len % 10 + '0';
                        cipher_len /= 10;
                    }
                    raw_msg.sz[4] = 0;
                    send_msg(raw_msg, ctx.server_fd);

                    memset(&raw_msg, 0, sizeof(raw_msg));
                }
                if(raw_msg.type == CON){
                    printf("Connect\n");
                    char addr[256] = {0};
                    strncpy(addr, &(buf[m]), 256);
                    m += strlen(addr) + 1;
                    if ((ctx.server_fd = server_connect(addr, PORT)) < 0){
                        printf("server connection error!\n");
                    }
                }

        }
        bzero(buf_start, (BUFLEN*i));
        i = 1;
        buf = buf_start;
        //buf_sz = 0;
    }
}

void exit_func(ctx *exit_ctx){
    shutdown(exit_ctx->ui_sock, SHUT_RDWR);
    shutdown(exit_ctx->server_fd, SHUT_RDWR);
    close(exit_ctx->ui_sock);
    close(exit_ctx->server_fd);
}

