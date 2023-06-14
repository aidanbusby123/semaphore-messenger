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
#define BUFLEN 512
const char MAGIC[3] = {0x69, 0x69, 0};

int main(){
    // define variables
    int proc_fd; // process file descriptor
    char buf[BUFLEN];
    ctx ctx;

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
    }
    while((c = fgetc(pub_fp)) != EOF){
        ctx.pub_key[i] = c;
    }

    // init threads

    if ((proc_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){ // create socket to allow communication between UI and client process
        perror("proc_fd socket");
    }

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

    int ui_sock = accept(proc_fd, (struct sockaddr*)&ui, &ui_len);

    bzero(buf, BUFLEN);

    msg raw_msg, out_msg;

    while (read(ui_sock, buf, BUFLEN) != -1){
        if (strncmp(MAGIC, buf, strlen(MAGIC)-1) != 0){
            printf("ui message: incorrect formating\n");
        }
        while (read(ui_sock, buf, BUFLEN) != -1){
            if (strncmp(MAGIC, buf, strlen(MAGIC)-1) != 0){ // keep getting data until end of transmission
                // get message type
                if (buf[0] == CA){
                    raw_msg.type = CA;
                    out_msg.type = CA;
                    bzero(buf, BUFLEN);
                    if (read(ui_sock, buf, BUFLEN) != -1){
                        strcpy(raw_msg.recv_pub_key, buf);
                    }
                    bzero(buf, BUFLEN);
                    if (read(ui_sock, buf, BUFLEN) != -1){
                        strcpy(raw_msg.send_pub_key, buf);
                    }
                    bzero(buf, BUFLEN);
                    if (read(ui_sock, buf, BUFLEN != -1)){
                        strcpy(raw_msg.timestamp, buf);
                        if (atoi(raw_msg.timestamp) > time(NULL)){
                            printf("invalid timestamp\n");
                        }
                    }
                    bzero(buf, BUFLEN);
                    if (read(ui_sock, buf, BUFLEN) != -1){
                        raw_msg.sz = atoi(buf);
                    }
                    bzero(buf, BUFLEN);

                    int bytes_read = 0;

                    while (bytes_read < raw_msg.sz && (read(ui_sock, buf, BUFLEN) != -1)){
                        strcat(raw_msg.content, buf);
                        bzero(buf, BUFLEN);
                    }

                    bzero(buf, BUFLEN);

                    strcpy(out_msg.recv_pub_key, raw_msg.recv_pub_key);
                    strcpy(out_msg.send_pub_key, raw_msg.send_pub_key);

                    // Encrypt certificate key (RSA)

                    if ((out_msg.sz = private_encrypt((unsigned char*)raw_msg.content, raw_msg.sz, ctx.priv_key, raw_msg.cipher)) == -1){ // encrypt message
                        printf("message encryption error\n");
                    }

                    out_msg.cipher = malloc(strlen(raw_msg.cipher)); // get cipher size

                    for (int i = 0; i < out_msg.sz; i++){ // store cipher in out_msg
                        out_msg.cipher[i] = raw_msg.cipher[i];
                    }

                    unsigned char **temp_checksum = sha256(raw_msg.content, (size_t)raw_msg.sz, NULL);
                    for (int i = 0; i < 32; i++){
                        out_msg.checksum[i] = *temp_checksum[i];
                    }
                    out_msg.checksum[32] = 0;

                    strcpy(out_msg.timestamp, raw_msg.timestamp);

                    send_msg(out_msg, ctx.server_fd);

                    memset(&raw_msg, 0, sizeof(raw_msg));
                    memset(&out_msg, 0, sizeof(out_msg));
                }
                if (buf[0] == MESSAGE){
                    raw_msg.type = MESSAGE;
                    bzero(buf, BUFLEN);
                    if (read(ui_sock, buf, BUFLEN) != -1){
                        strcpy(raw_msg.recv_pub_key, buf);
                    }
                    bzero(buf, BUFLEN);
                    if (read(ui_sock, buf, BUFLEN) != -1){
                        strcpy(raw_msg.send_pub_key, buf);
                    }
                    bzero(buf, BUFLEN);
                    if (read(ui_sock, buf, BUFLEN != -1)){
                        strcpy(raw_msg.timestamp, buf);
                        if (atoi(raw_msg.timestamp) > time(NULL)){
                            printf("invalid timestamp\n");
                        }
                    }
                    bzero(buf, BUFLEN);
                    if (read(ui_sock, buf, BUFLEN) != -1){
                        raw_msg.sz = atoi(buf);
                    }
                    bzero(buf, BUFLEN);

                    int bytes_read = 0;

                    while (bytes_read < raw_msg.sz && (read(ui_sock, buf, BUFLEN) != -1)){
                        strcat(raw_msg.content, buf);
                        bzero(buf, BUFLEN);
                    }
                    if (read(ui_sock, buf, BUFLEN != -1)){
                        strcpy(raw_msg.checksum, buf);
                    }
                    bzero(buf, BUFLEN);

                    // Encrypt messsage (RSA)

                    if (private_encrypt((unsigned char*)raw_msg.content, raw_msg.sz, ctx.priv_key, (unsigned char*)raw_msg.cipher) == -1){
                        printf("message encryption error\n");
                    }

                }
                if (buf[0] == CON){
                    char addr[256] = {0};
                    int port;
                    if (read(ui_sock, buf, BUFLEN) != -1){
                        if (strlen(addr) >= 256){
                            printf("addr overflow\n");
                        } else {
                            strncpy(addr, buf, strlen(buf));
                            if (read(ui_sock, buf, BUFLEN) != -1){
                                if (strlen(buf) <= 5){
                                    port = atoi(buf);
                                }
                                bzero(buf, BUFLEN);

                                ctx.server_fd = server_connect(addr, port); // connect to target server (onion routing)
                            }
                        }
                    }
                }
            } else {
                break;
            }
        }
    }
}

