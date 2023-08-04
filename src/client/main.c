#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<time.h>
#include<pthread.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<sys/un.h>
#include<openssl/ssl.h>
#include<openssl/sha.h>
#include<openssl/rsa.h>
#include<openssl/evp.h>
#include<openssl/bio.h>
#include<openssl/rand.h>
#include"common.h"

#define PROC_SOCK "/tmp/carbide-client.sock"

const char b64_charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const char b64_inv[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };

const char TX_START[4] = {0x66, 0x26, 0x07, 0x01};
const char TX_END[4] = {0x31, 0x41, 0x59, 0x26};

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

    ctx.rsa_priv_key_s = malloc(priv_key_sz+1);
    ctx.rsa_pub_key_s = malloc(pub_key_sz+1);

    fread(ctx.rsa_priv_key_s, sizeof(unsigned char), priv_key_sz, priv_fp);
    ctx.rsa_priv_key_s[priv_key_sz] = 0;
    
    fread(ctx.rsa_pub_key_s, sizeof(unsigned char), pub_key_sz, pub_fp);
    ctx.rsa_pub_key_s[pub_key_sz] = 0;

    ctx.rsa_priv_key = createRSA(ctx.rsa_priv_key_s, PRIVATE);
    ctx.rsa_pub_key = createRSA(ctx.rsa_pub_key_s, PUBLIC);

    fclose(priv_fp);
    fclose(pub_fp);

    ctx.addr = malloc(SHA256_DIGEST_LENGTH);
    memcpy(ctx.addr, SHA256(ctx.rsa_pub_key_s, strlen(ctx.rsa_pub_key_s), NULL), SHA256_DIGEST_LENGTH);

    ctx.pubkeys = NULL;
    ctx.pubkey_count = 0;
    ctx.aes_keys = NULL;
    ctx.keyring_sz = 0;

    if (load_pubkeys(&ctx) == -1){
        printf("Error: loading pubkeys failed\n");
        return -1;
    }
    if (load_keys(&ctx) == -1){
        printf("Error: loading keys failed\n");
        return -1;
    }
    if ((res = pthread_create(&recv_thread, NULL, recv_msg, (void*)&ctx)) != 0){ // create recieving thread
        printf("Error: failed to initialize recv_thread");
        return -1;
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

    unsigned int sz;
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    unsigned char *cipher; // encrypted message
    buf = malloc(BUFLEN*sizeof(char));
    buf_start = buf;
    bzero(buf, BUFLEN);
    bzero(temp_buf, BUFLEN);

    msg raw_msg;

    raw_msg.recv_addr = malloc(SHA256_DIGEST_LENGTH+1);
    raw_msg.send_addr = ctx.addr;

    int buf_sz = 0;
    int buf_len = 0;
    i = 1; 
    // main loop, process data from proc_fd and handle program execution, send messages
    while (1){
        while ((res = read(ctx.ui_sock, buf + ((i-1) * BUFLEN), BUFLEN))){
            buf_len += res;
            buf = buf_start;
            if (res == BUFLEN){
                buf = realloc(buf, BUFLEN*(i+1));
                buf_start = buf;
                buf_sz++;
                i++;
            } else {
                if (memcmp(buf + buf_len - sizeof(TX_END), &TX_END, sizeof(TX_END)) == 0){
                    break;
                } else{
                    continue;
                }
            }

        }    
    write(STDOUT_FILENO, buf, buf_len);
        if (buf_len > (2 * sizeof(TX_START) + 4)){
                // parse buffer
                int m = sizeof(TX_START);
                raw_msg.type = buf[m];
                m+=1;
                if (raw_msg.type == PUBKEY_REQ){
                    // send RSA key
                    if (buf_len == (2 * sizeof(TX_START) + sizeof(raw_msg.timestamp) + sizeof(raw_msg.type) + SHA256_DIGEST_LENGTH)){
                        memcpy(raw_msg.recv_addr, &buf[m], SHA256_DIGEST_LENGTH);
                        m += SHA256_DIGEST_LENGTH;
                        memcpy(&raw_msg.timestamp, &buf[m], sizeof(raw_msg.timestamp));
                        raw_msg.content = calloc(1, 1);
                        raw_msg.sz = 1;
                        unsigned char *sig_hash;
                        sig_hash = SHA256(raw_msg.content, 1, NULL);
                        raw_msg.signature = malloc(RSA_size(ctx.rsa_priv_key));
                        if ((raw_msg.sig_len = private_encrypt(sig_hash, SHA256_DIGEST_LENGTH, ctx.rsa_priv_key, raw_msg.signature)) == -1){
                            printf("Error: signature encryption failed (main)\n");
                        }
                        send_msg(raw_msg, ctx.server_fd); // send certificate
                        free(raw_msg.content);
                        free(raw_msg.signature);
                    }

                } else if(raw_msg.type == CON){
                    printf("Connect\n");
                    char addr[256] = {0};
                    if (strchr(&buf[0], 0) == NULL){
                        printf("Improperly formatted IPv4 address!\n");
                    } else {
                        strncpy(addr, &(buf[m]), 256);
                        m += strlen(addr) + 1;
                        if ((ctx.server_fd = server_connect(addr, PORT, DEFAULT)) < 0){
                            printf("server connection error!\n");
                        }
                        ctx.stat.connected = 1;
                    }
                }else if(raw_msg.type == MESSAGE){
                    printf("Message\n");
                    if (parse_ui_txt_msg(&raw_msg, &ctx, &buf[sizeof(TX_START)]) != -1){
                        send_msg(raw_msg, ctx.ui_sock);
                        if (format_txt_msg(&raw_msg, &ctx) != -1){
                            send_msg(raw_msg, ctx.server_fd);
                            store_txt_msg(&raw_msg, char_to_hex(raw_msg.recv_addr, SHA256_DIGEST_LENGTH));
                        }
                    }
                } else {
                    printf("Message format error\n");
                }
                raw_msg.type = 0;
                raw_msg.timestamp = 0;
                raw_msg.sz = 0;
        }
        i = 1;
        free(buf);
        buf = malloc(BUFLEN);
        buf_start = buf;
        buf_sz = 0;
        buf_len = 0;
    }
}

void exit_func(ctx *exit_ctx){
    shutdown(exit_ctx->ui_sock, SHUT_RDWR);
    shutdown(exit_ctx->server_fd, SHUT_RDWR);
    close(exit_ctx->ui_sock);
    close(exit_ctx->server_fd);
}
