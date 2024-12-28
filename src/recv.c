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
    unsigned char *raw_buf;
    unsigned char *raw_buf_start;
    int res;
    int raw_buf_sz = 0;
    int buf_len = 0;
    int raw_buf_len = 0;
    int i = 1;

    ctx_p = ((ctx*)arg);

    raw_buf = malloc(BUFLEN);
    raw_buf_start = raw_buf;

    in_msg.send_addr = malloc(SHA256_DIGEST_LENGTH);
    in_msg.recv_addr = malloc(SHA256_DIGEST_LENGTH);
    memcpy(in_msg.recv_addr, ctx_p->addr, SHA256_DIGEST_LENGTH);

    while (1){
        while (ctx_p->stat.connected == 1){
            while ((res = read(ctx_p->server_fd, raw_buf + ((i-1) * BUFLEN), BUFLEN))){
                raw_buf_len += res;
                raw_buf = raw_buf_start;
                if (res == BUFLEN){
                    raw_buf = realloc(raw_buf, BUFLEN*(i+1));
                    raw_buf_start = raw_buf;
                    raw_buf_sz++;
                    i++;
                } else {
                    if (memcmp(raw_buf + raw_buf_len - sizeof(TX_END), &TX_END, sizeof(TX_END)) == 0){
                        raw_buf_sz = 0;
                        break;
                    } else{
                        continue;
                    }
                }

            }
            if (raw_buf_len > (2*sizeof(TX_START) + 4)){
                if ((buf_len = b64_decode(raw_buf+sizeof(TX_START), raw_buf_len-sizeof(TX_END), &buf)) < 0){
                    printf("Error: recv: unable to decode message buf from base64\n");
                }
            }   
            printf("recv:\n");
            write(STDOUT_FILENO, buf, buf_len);
            if (buf_len > (2 * sizeof(TX_START) + 4)){
                int m = 0;
                in_msg.type = buf[m];
                m += sizeof(in_msg.type);
                if (in_msg.type == MESSAGE){
                    printf("Message recieved\n");
                    if (buf_len < (2 * sizeof(TX_START) + 4 + SHA256_DIGEST_LENGTH * 2 + sizeof(in_msg.timestamp) + sizeof(in_msg.sz) + sizeof(in_msg.sig_len))){
                        printf("Error: recieved incorrectly formatted MESSAGE\n");
                    }
                    parse_txt_msg(&in_msg, ctx_p, &buf[0], buf_len);
                    store_txt_msg(&in_msg, ctx_p, char_to_hex(in_msg.send_addr, SHA256_DIGEST_LENGTH));

                }else if (in_msg.type == PUBKEY_REQ){ // if recieved message is public key exchange request

                    if (buf_len < (2 * sizeof(TX_START) + 4 + SHA256_DIGEST_LENGTH * 2 + sizeof(in_msg.timestamp) + sizeof(in_msg.sz) + sizeof(in_msg.sig_len))){
                        printf("Error: recieved incorrectly formatted PUBKEY_REQ\n");
                    }
                    m += SHA256_DIGEST_LENGTH;
                    memcpy(in_msg.send_addr, &buf[0], SHA256_DIGEST_LENGTH);
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

                } else if (in_msg.type == DISCON){

                    printf("DISCON\n");
                    if (server_disconnect(*ctx_p) < 0){
                        printf("Error: server disconnect failed");
                    }

                }
            }
            free(buf);
            free(raw_buf);
            raw_buf = malloc(BUFLEN);
            raw_buf_start = raw_buf;
            i = 1;
            buf_len = 0; 
            raw_buf_len = 0;
            raw_buf_sz = 0;
        }
    }
}
