#include<stdio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include"common.h"

#define PUBLIC 0
#define PRIVATE 1

int padding = RSA_PKCS1_PADDING;

RSA* createRSA(unsigned char* key, int type){
    RSA *rsa = NULL;
    BIO* keybio;
    keybio = BIO_new_mem_buf(key, -1);

    if (keybio == NULL){
        printf("unable to create key BIO\n");
        return 0;
    }
    if (type == PUBLIC){
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else if (type == PRIVATE) {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if (rsa == NULL){
        printf("failed to create RSA\n");
    }
    return rsa;
}

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

unsigned char** sha256(unsigned char *d, size_t n, unsigned char *md){
    unsigned char* hash_temp = SHA256(d, n, md);
    unsigned char** hash = (unsigned char**)malloc(sizeof(unsigned char)*(32+1));
    for (int i = 0; i < 32; i++){
        *hash[i] = hash_temp[i];
    }
    *hash[32] = 0;
    return hash;
}

