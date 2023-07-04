#include<stdio.h>
#include<string.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include"common.h"

int padding = RSA_PKCS1_PADDING;

RSA* createRSA(unsigned char* key, int type){
    RSA *rsa = NULL;
    BIO* keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL){
        printf("unable to create key BIO\n");
        return NULL;
    }
    if (type == PUBLIC){
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else if (type == PRIVATE) {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
    if (rsa == NULL){
        printf("failed to create RSA\n");
        return NULL;
    }
    return rsa;
}

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){
    RSA * rsa = createRSA(key, PUBLIC);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    if (result == -1){
        printf("%s", ERR_error_string(ERR_get_error(), NULL));
    }
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){
    RSA * rsa = createRSA(key, PRIVATE);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted){
    RSA * rsa = createRSA(key, PRIVATE);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    if (result == -1){
        printf("%s", ERR_error_string(ERR_get_error(), NULL));
    }
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted){
    RSA * rsa = createRSA(key, PUBLIC);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

int rsa_sz(unsigned char* key, int type){
    int sz;
    RSA *rsa = createRSA(key, type);
    sz = RSA_size(rsa);
    return sz;
}

unsigned char* sha256(unsigned char *d, size_t n, unsigned char *md){ // return string version of sha256 hash
    unsigned char* hash_temp = SHA256(d, n, md);
    unsigned char* hash = malloc(2 * SHA256_DIGEST_LENGTH + 1);
    hash = char_to_hex(hash_temp);
    hash[2*SHA256_DIGEST_LENGTH] = 0;
    return hash;
}

unsigned char* char_to_hex(unsigned char *s){
    int sz = strlen(s);
    unsigned char *hex = malloc(2 * sz + 1);
    for (int i = 0; i < sz; i++){
        hex[2 * i] = ((s[i]/16) >= 10) ? ('a' + s[i]/16 - 10) : (s[i] / 16) + '0';
        hex[2 * i + 1] = ((s[i] - ((s[i]/16) * 16)) >= 10) ? ('a' + (s[i] - ((s[i]/16) * 16)) - 10) : s[i] - (s[i]/16) * 16 + '0';
    }
    return hex;
}
