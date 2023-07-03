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

int server_connect(char *addr_s, int port){ // connect to server
    int sock_fd;
    struct sockaddr_in addr;
    memset((char*)&addr, 0, sizeof(addr));

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("cannot create socket");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
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

    return sock_fd;
    
}

int send_msg(msg message, int server_fd){ // format and send message to server
    int msg_buf_len = atoi(message.sz) + 1 + 2*strlen(MAGIC) + 1 + 2 + strlen(message.recv_pub_key) + 1 + strlen(message.send_pub_key) + 1 + strlen(message.timestamp) + 1 + strlen(message.sz) + 1 + strlen(message.checksum) + 1 + 1 + 1;
    unsigned char *msg_buf = (unsigned char*)malloc(msg_buf_len); // message buffer
    unsigned char type_s[2] = {0}; // message.type string representation
    // Transfer data to msg_buf
    printf("msg_buf:\n");
    strcpy(msg_buf, MAGIC);
    printf("%s\n", msg_buf);
    msg_buf += strlen(MAGIC) + 1;
    type_s[0] = message.type;
    strcat((char*)(msg_buf), type_s);
    printf("%s\n", msg_buf);
    msg_buf += strlen(type_s) + 1;
    strcat((char*)(msg_buf), message.recv_pub_key);
    printf("%s\n", msg_buf);
    msg_buf += strlen(message.recv_pub_key) + 1;
    strcat((char*)(msg_buf), message.send_pub_key);
    printf("%s\n", msg_buf);
    msg_buf += strlen(message.send_pub_key) + 1;
    strcat((char*)(msg_buf), message.timestamp);
    printf("%s\n", msg_buf);
    msg_buf += strlen(message.timestamp) + 1;
    strcat((char*)(msg_buf), message.sz);
    printf("%s\n", msg_buf);
    msg_buf += strlen(message.sz) + 1;
    strcat((char*)(msg_buf), message.cipher);
    printf("%s\n", msg_buf);
    msg_buf += strlen(message.cipher);
    strcat((char*)(msg_buf), message.checksum);
    printf("%s\n", msg_buf);
    msg_buf += strlen(message.checksum);
    strcat((char*)(msg_buf), MAGIC);
    printf("%s\n", msg_buf);
    msg_buf = &(msg_buf[0]);
    int res = 0;
    while ((res = send(server_fd, msg_buf, msg_buf_len, 0)) > 0){
        if (res == -1){
            printf("message send error\n");
            break;
        }
    }
}