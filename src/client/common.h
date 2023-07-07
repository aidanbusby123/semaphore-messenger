#include<stdio.h>

#ifndef COMMON_H
#define COMMON_H

#define MESSAGE 0x01
#define CA 0x02
#define CON 0x03

#define BUFLEN 1024
#define KEY_SZ 4096

#define PUBLIC 0
#define PRIVATE 1

#define PORT 8080
#define TOR_PORT 9050

// connection modes
#define DEFAULT 0
#define TOR 1
//

#define SHA256_SZ 32
extern const char MAGIC[2];

typedef struct msg{
    unsigned char type;
    unsigned char *recv_addr; // receiver address (hash of public key)
    unsigned char *send_addr; // sender address (hash of public key)
    unsigned int timestamp; // timestamp of message
    unsigned int sz;
    unsigned char checksum[SHA256_SZ];
    unsigned char *cipher; // encrypted message
    unsigned char *content; // decrypted message content
}msg;

struct status{
    int connected;
};

typedef struct ctx{
    int server_fd; // server socket fd
    int ui_sock; // UI socket
    struct status stat;
    unsigned char *addr;
    unsigned char *pub_key;
    unsigned char *priv_key;
}ctx;

int server_connect(char *addr_s, int port, int mode);

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);

int rsa_sz(unsigned char* key, int type);

unsigned char* sha256(unsigned char *d, size_t n, unsigned char *md);

int send_msg(msg message, int server_fd); // send message
void *recv_msg(void *arg); // handle the reception of messages

FILE* open_file(char *file);
int fsize(FILE* fp);

#endif