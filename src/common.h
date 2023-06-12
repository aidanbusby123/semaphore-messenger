#include<stdio.h>
#ifndef COMMON_H
#define COMMON_H

#define CA 0x01
#define MESSAGE 0x02

extern const char MAGIC[3];

typedef struct msg{
    int type;
    char *recv_pub_key; // receiver (user) public key
    char *send_pub_key; // sender public key
    int timestamp; // timestamp of message
    int sz;
    char *cipher; // encrypted message
    char checksum[32];
    
    char *content; // decrypted message content
}msg;

typedef struct ctx{
    char pub_key[8192];
    char priv_key[8192];
}ctx;

int check_msg(msg m); // get checksum of message, compare with provided checksum to ensure authenticity 
int store_msg(msg m); // store received messages on drive

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);

int send_msg(char *message, char *dest_public_key, char *private_key); // send message

void *recv_msg_thread(void *arg); // receiving thread

FILE* open_file(char *file);

#endif