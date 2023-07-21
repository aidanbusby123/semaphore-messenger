#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<time.h>
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

    in_msg.send_addr = malloc(SHA256_DIGEST_LENGTH);
    in_msg.recv_addr = malloc(SHA256_DIGEST_LENGTH);
    memcpy(in_msg.recv_addr, ctx_p->addr, SHA256_DIGEST_LENGTH);

    while (1){
        while (ctx_p->stat.connected == 1){
            while ((res = read(ctx_p->server_fd, buf + ((i-1) * BUFLEN), BUFLEN))){
                buf_len += res;
                buf = buf_start;
                if (buf_len == BUFLEN){
                    buf = realloc(buf, BUFLEN*(i+1));
                    buf_start = buf;
                    buf_sz++;
                    i++;
                } else {
                    if (memcmp(buf + buf_len - sizeof(MAGIC), MAGIC, sizeof(MAGIC)) == 0){
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

                if (in_msg.type == MESSAGE){
                    if (buf_len < (2 * sizeof(MAGIC) + 4 + SHA256_DIGEST_LENGTH * 2 + sizeof(in_msg.timestamp) + sizeof(in_msg.sz) + sizeof(in_msg.sig_len))){
                        printf("Error: recieved incorrectly formatted MESSAGE\n");
                    }
                    parse_txt_msg(&in_msg, ctx_p, &buf[0], buf_len);
                    for (int k = 0; k < in_msg.sz; k++){
                        putchar(in_msg.content[k]);
                    }
                    printf("\n");
                }else if (in_msg.type == PUBKEY_REQ){ // if recieved message is public key exchange request
                    if (buf_len < (2 * sizeof(MAGIC) + 4 + SHA256_DIGEST_LENGTH * 2 + sizeof(in_msg.timestamp) + sizeof(in_msg.sz) + sizeof(in_msg.sig_len))){
                        printf("Error: recieved incorrectly formatted PUBKEY_REQ\n");
                    }
                    m += SHA256_DIGEST_LENGTH;
                    memcpy(in_msg.send_addr, &buf[m], SHA256_DIGEST_LENGTH);
                    printf("PUBKEY_REQ\n");
                    if (format_pubkey_x_msg(&in_msg, ctx_p, &buf[0]) == -1){
                        printf("Error: unable to format pubkey msg\n");
                        return NULL;
                    }
                    send_msg(in_msg, ctx_p->server_fd);
                    in_msg.content = NULL;

                    if (!pubkey_known(char_to_hex(in_msg.send_addr, SHA256_DIGEST_LENGTH))){ // send PUBKEY_REQ to sender
                        printf("PUBKEY_REQ automatic resp\n");
                        in_msg.type = PUBKEY_REQ;
                        in_msg.timestamp = time(NULL);
                        in_msg.content = calloc(1, 1);
                        in_msg.sz = 1;
                        send_msg(in_msg, ctx_p->server_fd);
                    } 
                } else if (in_msg.type == PUBKEY_X){ // recieved public key
                    printf("PUBKEY_X\n");
                    if (parse_pubkey_x_buf(&in_msg, ctx_p, &buf[0], buf_len) == -1){
                        printf("Error: unable to extract pubkey from buf\n");
                        return NULL;
                    }
                    if (format_key_x_msg(&in_msg, ctx_p) == -1){
                        printf("Error: unable to format shared key msg\n");
                        return NULL;
                    }
                    send_msg(in_msg, ctx_p->server_fd);
                } else if (in_msg.type == KEY_X){
                    printf("KEY_X\n");
                    if (parse_key_x_buf(&in_msg, ctx_p, &buf[0], buf_len) == -1){
                        printf("Error: unable to extract shared key from buf\n");
                    }

                }
            }
            free(buf);
            i = 1;
            buf = malloc(BUFLEN);
            buf_start = buf;
            buf_sz = 0;
            buf_len = 0; 
        }
    }
}
