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

int send_msg(msg message, int server_fd){ // format and send message to server
    int msg_buf_len = message.sz + 2*(sizeof(MAGIC)) + sizeof(message.type) + SHA256_SZ * 2 + sizeof(message.timestamp) + sizeof(message.sz) + sizeof(message.checksum);
    unsigned char *msg_buf = (unsigned char*)malloc(msg_buf_len); // message buffer
    unsigned char *msg_buf_start = msg_buf;
    int res = 0;
    int bytes_wrote = 0;
    // Transfer data to msg_buf
    memcpy(msg_buf, &MAGIC, sizeof(MAGIC));
    msg_buf += sizeof(MAGIC);
    memcpy(msg_buf, &message.type, sizeof(message.type));
    msg_buf += sizeof(message.type);
    memcpy(msg_buf, message.recv_addr, SHA256_SZ);
    msg_buf += SHA256_SZ;
    memcpy(msg_buf, message.send_addr, SHA256_SZ);
    msg_buf += SHA256_SZ;
    memcpy(msg_buf, &message.timestamp, sizeof(message.timestamp));
    msg_buf += sizeof(message.timestamp);
    memcpy(msg_buf, &message.sz, sizeof(message.sz));
    msg_buf += sizeof(message.sz);
    memcpy(msg_buf, message.content, message.sz);
    msg_buf += message.sz;
    memcpy(msg_buf, message.checksum, SHA256_SZ);
    msg_buf += SHA256_SZ;
    memcpy(msg_buf, &MAGIC, sizeof(MAGIC));
    msg_buf = msg_buf_start;
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

