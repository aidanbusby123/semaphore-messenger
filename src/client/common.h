#include<stdio.h>
#include<openssl/ssl.h>
#include<openssl/pem.h>
#include<openssl/sha.h>
#include<openssl/rsa.h>

#ifndef COMMON_H
#define COMMON_H

extern const char TX_START[4];
extern const char TX_END[4];

#define MESSAGE 0x01
#define PUBKEY_REQ 0x02
#define PUBKEY_X 0x03
#define KEY_X 0x04
#define CON 0x05
#define CONFIG 0x06

#define BUFLEN 1024
#define RSA_KEY_SZ 4096
#define AES_KEY_SZ 256
#define IV_SZ 128

#define PUBLIC 0
#define PRIVATE 1

#define PORT 8080
#define TOR_PORT 9050

// connection modes
#define DEFAULT 0
#define TOR 1

extern const char b64_charset[];
extern const char b64_inv[];

typedef struct msg{
    unsigned char type;
    unsigned char *recv_addr; // receiver address (hash of public key)
    unsigned char *send_addr; // sender address (hash of public key)
    unsigned int timestamp; // timestamp of message
    unsigned int sz;
    unsigned char *content; // message content
    unsigned int sig_len; // length of signature
    unsigned char *signature; // signature buffer
}msg;

typedef struct aes_keyring{
    unsigned char addr[2*SHA256_DIGEST_LENGTH];
    unsigned char key[256/8];
}aes_keyring;

typedef struct pubkey_ring{
    unsigned char addr[2*SHA256_DIGEST_LENGTH];
    RSA *pubkey;
}pubkey_ring;

struct status{
    int connected;
};

typedef struct ctx{
    int server_fd; // server socket fd
    int ui_sock; // UI socket
    long unsigned int keyring_sz;
    long unsigned int pubkey_count;
    struct status stat;
    unsigned char *master_key; // master aes key, used to encrypt/decrypt all sensitive information on disk/memory
    unsigned char *addr;
    RSA *rsa_pub_key;
    unsigned char *rsa_pub_key_s;
    RSA *rsa_priv_key;
    unsigned char *rsa_priv_key_s;
    RSA *rsa_dest_key; // public key of recieved message
    aes_keyring *aes_keys;
    pubkey_ring *pubkeys; // public keys of known contacts
    unsigned char *msg_file;
}ctx;

// Message transfer

int send_msg(msg message, int server_fd); // send message
void *recv_msg(void *arg); // handle the reception of messages

int server_connect(char *addr_s, int port, int mode);

// AES encryption
int encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *iv, unsigned char *cipher);
// AES decryption
int decrypt(unsigned char *cipher, int cipher_len, unsigned char *key, unsigned char *iv, unsigned char *data);

// load AES keyring indice
unsigned char* load_key_ring(unsigned char *name, ctx *ctx_p);
// public/private key encryption

int public_encrypt(unsigned char * data,int data_len, RSA *rsa, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len, RSA *rsa, unsigned char *decrypted);
int private_encrypt(unsigned char * data,int data_len, RSA *rsa, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len, RSA *rsa, unsigned char *decrypted);

RSA* createRSA(unsigned char *key, int type);

//public key storage handling

int store_pubkey(unsigned char *data, int data_len, unsigned char *name); // store RSA key
RSA* load_pubkey_ring(unsigned char *name, ctx *ctx_p); // load RSA key from key buffer
int load_pubkey(unsigned char *name, ctx *ctx_p); // load singular RSA public key file from specified address
int load_pubkeys(ctx *ctx_p); // load RSA public keys from PEM files

// key storage handling
int store_key(unsigned char *data, int data_len, unsigned char *name); // store AES shared key
int load_key(unsigned char *addr, ctx *ctx_p); // load singular AES key from specified address
int load_keys(ctx *ctx_p); // load AES private keys from file, store in keyring

// parse txt message from client UI
int parse_ui_txt_msg(msg *msg_p, ctx *ctx_p, unsigned char *buf);

int format_txt_msg(msg *msg_p, ctx *ctx_p); // format plaintext message
int parse_txt_msg(msg *msg_p, ctx *ctx_p, unsigned char *buf, int buf_len); // parse text message

// public/private key message exchange 
int format_pubkey_x_msg(msg *msg_p, ctx *ctx_p, unsigned char *buf); // format message to send RSA key data 
int format_key_x_msg(msg *msg_p, ctx *ctx_p); // format msg to send shared AES key data
int parse_pubkey_x_buf(msg *msg_p, ctx *ctx_p, unsigned char *buf, int buf_len); // extract RSA public key data from recieved buffer
int parse_key_x_buf(msg *msg_p, ctx* ctx_p, unsigned char *buf, int buf_len); // extract shared AES key data from recieved buffer

int store_txt_msg(msg *msg_p, unsigned char *addr); // store txt message on disk

// File functions
FILE* open_file(char *file);
int fsize(FILE* fp);
int isfile(unsigned char *fname);
int pubkey_known(unsigned char *addr);

unsigned char* char_to_hex(unsigned char *s, int len); // convert raw char data into hexadecimal representation

// base64 encode/decode

int b64_encode(unsigned char *in, unsigned long int in_len, unsigned char **out);
int b64_decode(unsigned char *in, unsigned long int in_len, unsigned char **out);
#endif