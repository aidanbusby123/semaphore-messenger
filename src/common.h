#include<stdio.h>
#include<openssl/sha.h>
#ifndef COMMON_H
#define COMMON_H

#define MESSAGE 0x01
#define CA 0x02
#define CON 0x03

#define KEY_SZ 4096

#define PUBLIC 0
#define PRIVATE 1

#define PORT 9050

extern const char MAGIC[3];

typedef struct msg{
    unsigned char type;
    unsigned char *recv_pub_key; // receiver (user) public key
    unsigned char *send_pub_key; // sender public key
    unsigned char timestamp[21]; // timestamp of message
    unsigned char sz[5];
    unsigned char checksum[SHA256_DIGEST_LENGTH*2+1];
    unsigned char *cipher; // encrypted message
    unsigned char *content; // decrypted message content
}msg;

typedef struct ctx{
    int server_fd; // server socket fd
    int ui_sock; // UI socket
    unsigned char *pub_key;
    unsigned char *priv_key;
}ctx;

int server_connect(char *addr_s, int port);

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);

int rsa_sz(unsigned char* key, int type);

unsigned char* sha256(unsigned char *d, size_t n, unsigned char *md);

unsigned char* char_to_hex(unsigned char *s); // convert raw char array to hex representatio

int send_msg(msg message, int server_fd); // send message

void *recv_msg_thread(void *arg); // receiving thread

FILE* open_file(char *file);
int fsize(FILE* fp);

#endif