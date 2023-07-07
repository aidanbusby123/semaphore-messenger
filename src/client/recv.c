#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include"common.h"

void *recv_msg(void *arg){ // handle the reception of messages
    ctx *ctx_p; //ctx pointer
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
            free(buf);
            i = 1;
            buf = realloc(buf, BUFLEN);
            buf_start = buf;
            buf_sz = 1;
            buf_len = 0; 
        }
    }
}