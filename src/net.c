#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<netdb.h>
#include<arpa/inet.h>
#include"common.h"

#define LOCALHOST "127.0.0.1"

int server_connect(char *addr_s, int port, int mode){ // connect to server
    int sock_fd;
    struct sockaddr_in addr;
    memset((char*)&addr, 0, sizeof(addr));

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("cannot create socket");
        return -1;
    }

    switch(mode){
        case DEFAULT:
            addr.sin_family = AF_INET;
            addr.sin_port = htons(PORT);
            addr.sin_addr.s_addr = inet_addr(addr_s);

            if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0){
                perror("connect failed");
            }
            break;
        
        case TOR:
            addr.sin_family = AF_INET;
            addr.sin_port = htons(TOR_PORT);
            addr.sin_addr.s_addr = inet_addr(LOCALHOST);

            if ((connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr))) < 0){
                perror("connect failed");
                return -1;
            }

            char req1[3] =
            {
                0x05, // SOCKS 5
                0x01, // One Authentication Method
                0x00  // No AUthentication
            };

            char resp1[2];

            send(sock_fd, req1, 3, MSG_NOSIGNAL);

            recv(sock_fd, resp1, 2, 0);

            if (resp1[1] != 0x00){
                perror("Authentication error");
                return -1;
            }

            int addr_len = strlen(addr_s);
            int prt = htons(port);


            char tmpreq[4] = {
                0x05, // SOCKS5
                0x01, // CONNECT
                0x00, // RESERVED
                0x03, // DOMAIN
            };

            char *req2 = malloc((4 + 1 + addr_len + 2) * sizeof(char));

            memcpy(req2, tmpreq, 4);                // 0x05, 0x01, 0x00, 0x03
            memcpy(req2 + 4, &addr_len, 1);        // Domain Length
            memcpy(req2 + 5, addr_s, addr_len);    // Domain
            memcpy(req2 + 5 + addr_len, &prt, 2); // Port

            char resp2[10];

            recv(sock_fd, resp2, 10, 0);

            if (resp2[0] != 0x00){
                printf("error: %c", resp2[1]);
                perror("");
                return -1;
            }

            printf("Tor connection successful!\n");
            break;
        
    }

    return sock_fd;
    
}

int server_disconnect(ctx ctx){
    if (close(ctx.server_fd) < 0){
        perror("Server disconnect error\n");
        return -1;
    } else {
        return 1;
    }
}

int ui_disconnect(ctx ctx){
    if (close(ctx.ui_sock) < 0){
        perror("UI disconnect error\n");
        return -1;
    } else {
        return 1;
    }
}

int send_msg(msg message, int server_fd){ // format and send message to server
    int raw_msg_buf_len = message.sz + sizeof(message.type) + SHA256_DIGEST_LENGTH * 2 + sizeof(message.timestamp) + sizeof(message.sz) + sizeof(message.sig_len) + message.sig_len;
    unsigned char *raw_msg_buf = (unsigned char*)malloc((unsigned int) raw_msg_buf_len); // message buffer
    unsigned char *raw_msg_buf_start = raw_msg_buf;
    unsigned char *msg_buf;
    unsigned char *temp_msg_buf;
    int msg_buf_len;
    int temp_msg_buf_len;
    int res = 0;
    int bytes_wrote = 0;
    // Transfer data to msg_buf
    if (message.type == MESSAGE || message.type == PUBKEY_REQ || message.type == PUBKEY_X || message.type == KEY_X){
        memcpy(raw_msg_buf, &message.type, sizeof(message.type));
        raw_msg_buf += sizeof(message.type);
        memcpy(raw_msg_buf, message.recv_addr, SHA256_DIGEST_LENGTH);
        printf("recv_addr: ");
        write(STDOUT_FILENO, message.recv_addr, 32);
        printf("\n");
        raw_msg_buf += SHA256_DIGEST_LENGTH;
        memcpy(raw_msg_buf, message.send_addr, SHA256_DIGEST_LENGTH);
        printf("send_addr: ");
        write(STDOUT_FILENO, message.send_addr, 32);
        printf("\n");
        raw_msg_buf += SHA256_DIGEST_LENGTH;
        memcpy(raw_msg_buf, &message.timestamp, sizeof(message.timestamp));
        raw_msg_buf += sizeof(message.timestamp);
        memcpy(raw_msg_buf, &message.sz, sizeof(message.sz));
        raw_msg_buf += sizeof(message.sz);
        memcpy(raw_msg_buf, message.content, message.sz);
        raw_msg_buf += message.sz;
        memcpy(raw_msg_buf, &message.sig_len, sizeof(message.sig_len));
        raw_msg_buf += sizeof(message.sig_len);
        memcpy(raw_msg_buf, message.signature, message.sig_len);
        raw_msg_buf += message.sig_len;
        raw_msg_buf_len = raw_msg_buf-raw_msg_buf_start;
        raw_msg_buf = raw_msg_buf_start;
        write(STDOUT_FILENO, raw_msg_buf, 2*raw_msg_buf_len);

    }else if (message.type == CON){
        memcpy(raw_msg_buf, &message.type, sizeof(message.type));
        raw_msg_buf += sizeof(message.type);
        memcpy(raw_msg_buf, message.send_addr, SHA256_DIGEST_LENGTH);
        raw_msg_buf += SHA256_DIGEST_LENGTH;
        memcpy(raw_msg_buf, &message.timestamp, sizeof(message.timestamp));
        raw_msg_buf += sizeof(message.timestamp);
        memcpy(raw_msg_buf, &message.sz, sizeof(message.sz));
        raw_msg_buf += sizeof(message.sz);
        memcpy(raw_msg_buf, message.content, message.sz);
        raw_msg_buf += message.sz;
        memcpy(raw_msg_buf, &message.sig_len, sizeof(message.sig_len));
        raw_msg_buf += sizeof(message.sig_len);
        memcpy(raw_msg_buf, message.signature, message.sig_len);
        raw_msg_buf += message.sig_len;
        raw_msg_buf_len = raw_msg_buf-raw_msg_buf_start;
        raw_msg_buf = raw_msg_buf_start;
    }

    if ((temp_msg_buf_len = b64_encode(raw_msg_buf, raw_msg_buf_len, &temp_msg_buf)) < 0){
        printf("Error: send_msg: unable to encode temp message buf in base64");
    }
    printf("sending: ");
    write(STDOUT_FILENO, temp_msg_buf, temp_msg_buf_len);
    printf("\n");
    msg_buf_len = sizeof(TX_START) + sizeof(TX_END) + temp_msg_buf_len;
    msg_buf = malloc(msg_buf_len);
    memcpy(msg_buf, TX_START, sizeof(TX_START));
    memcpy(msg_buf+sizeof(TX_START), temp_msg_buf, temp_msg_buf_len);
    memcpy(msg_buf+sizeof(TX_START) + temp_msg_buf_len, TX_END, sizeof(TX_END));
    printf("sending: \n");
    write(STDOUT_FILENO, msg_buf, msg_buf_len);
    while (res = send(server_fd, msg_buf, msg_buf_len, 0)){
        if (res == -1){
            printf("message send error\n");
            break;
        }
        bytes_wrote += res;
        if (bytes_wrote < msg_buf_len)
            continue;
        else
            return 0;
    }
}

