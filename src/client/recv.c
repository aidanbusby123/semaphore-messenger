#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include"common.h"

void *recv_msg(void *arg){ // handle the reception of messages
    ctx *ctx_p; //ctx pointer
    msg in_msg;
    unsigned char *buf;
    unsigned char *buf_start;
    int res;
    int buf_sz = 0;
    int buf_len = 0;
    int i = 1;

    ctx_p = ((ctx*)arg);

    buf = malloc(BUFLEN);
    buf_start = buf;

    while (1){
        while (ctx_p->stat.connected == 1){
            while ((res = read(ctx_p->server_fd, buf + ((i-1) * BUFLEN), BUFLEN))){
                for (int k = 0; k < res; k++){
                    putchar(buf[k]);
                }
                putchar('\n');
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
                    } else {
                        continue;
                    }
                }
            }
            if (buf_len > (2 * sizeof(MAGIC) + 4)){
                int m = 2;
                in_msg.type = buf[m];
                m += sizeof(in_msg.type);

                if (in_msg.type == CA){
                    if (buf_len > (sizeof(MAGIC) + sizeof(in_msg.type) + SHA256_SZ * 2 + sizeof(in_msg.timestamp) + sizeof(in_msg.sz) + SHA256_SZ + sizeof(MAGIC))){
                        m += SHA256_SZ;
                        memcpy(in_msg.send_addr, &buf[m], SHA256_SZ);
                        m += SHA256_SZ;
                        memcpy(in_msg.timestamp, &buf[m], sizeof(in_msg.timestamp));
                        m += sizeof(in_msg.timestamp);
                        memcpy(in_msg.sz, &buf[m], sizeof(in_msg.sz));
                        m += sizeof(in_msg.sz);
                        memcpy(in_msg.content, &buf[m], in_msg.sz);
                        m += in_msg.sz;
                        memcpy(in_msg.checksum, &buf[m], sizeof(in_msg.checksum));
                    }
                }
            }
            free(buf);
            i = 1;
            buf = realloc(buf, BUFLEN);
            buf_start = buf;
            buf_sz = 1;
            buf_len = 0; 
        }
    }
}
