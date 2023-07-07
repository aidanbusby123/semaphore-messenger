#include<stdio.h>
#include<string.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include"common.h"

const int padding = RSA_PKCS1_PADDING;

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
    unsigned char* hash = SHA256(d, n, md);
    return hash;
}

FILE *cert_gen(msg *msg, ctx *ctx){
    X509 *cert;
    cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    X509_set_pubkey(cert, ctx->pub_key);

    X509_NAME *name;
    name =  X509_get_subject_name(cert);

    X509_NAME_add_entry_by_txt(name, "sender_address", MBSTRING_ASC, msg->send_addr, -1, -1, 0);
    X509_set_issuer_name(cert, name);
    
    X509_sign(cert, ctx->pub_key, EVP_sha256());

    FILE *fp;
    fp = fopen("cert.pem", "wb");
    PEM_write_X509(fp, cert);
    return fp;
}
