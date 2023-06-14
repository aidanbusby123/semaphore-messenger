#include<stdio.h>
#ifndef COMMON_H
#define COMMON_H

#define MESSAGE 0x01
#define CA 0x02
#define CON 0x03

extern const char MAGIC[3];

typedef struct msg{
    int type;
    unsigned char *recv_pub_key; // receiver (user) public key
    unsigned char *send_pub_key; // sender public key
    unsigned char *timestamp; // timestamp of message
    int sz;
    unsigned char *cipher; // encrypted message
    unsigned char checksum[33];
    
    char *content; // decrypted message content
}msg;

typedef struct ctx{
    char pub_key[8192];
    char priv_key[8192];

    int server_fd;
}ctx;

int server_connect(char *addr_s, int port);

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);

unsigned char** sha256(unsigned char *d, size_t n, unsigned char *md);

int send_msg(msg message, int server_fd); // send message

void *recv_msg_thread(void *arg); // receiving thread

FILE* open_file(char *file);

#endif