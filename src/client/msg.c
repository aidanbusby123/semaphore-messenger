#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<openssl/sha.h>
#include<openssl/rand.h>
#include"common.h"

int format_pubkey_x_msg(msg *msg_p, ctx *ctx_p, unsigned char *buf){ // format message to send RSA key data
    int m = sizeof(MAGIC) + sizeof(msg_p->type) + SHA256_DIGEST_LENGTH;
    unsigned int content_len;
    int cipher_sz = strlen(ctx_p->rsa_pub_key_s);
    msg_p->type = PUBKEY_X;
    msg_p->sz = cipher_sz;
    msg_p->content = malloc(msg_p->sz);
    memcpy(msg_p->content, ctx_p->rsa_pub_key_s, msg_p->sz);

    memcpy(msg_p->recv_addr, &buf[m], SHA256_DIGEST_LENGTH); // set destination address
    m += SHA256_DIGEST_LENGTH;
                    
    msg_p->timestamp = *(unsigned int*)(&buf[m]);
    m += sizeof(msg_p->timestamp);

    unsigned char *sig_hash = malloc(SHA256_DIGEST_LENGTH);
    sig_hash = SHA256(msg_p->content, msg_p->sz, NULL);
    msg_p->signature = malloc(RSA_size(ctx_p->rsa_priv_key));
    if ((msg_p->sig_len = private_encrypt(sig_hash, SHA256_DIGEST_LENGTH, ctx_p->rsa_priv_key, msg_p->signature)) == -1){
        printf("Error: signature encryption failed\n");
        return -1;
    } 
}

int format_key_x_msg(msg *msg_p, ctx *ctx_p){ // format msg to send shared AES key data
    RSA *dest_key;
    int cipher_len;
    int cipher_sz;
    unsigned int content_len;
    unsigned char *temp_cipher;
    unsigned char *aes_key;
    unsigned char *temp_content = malloc(AES_KEY_SZ/8);
    unsigned char *seed = malloc(SHA256_DIGEST_LENGTH);
    unsigned char *addr_name;
    addr_name = malloc(SHA256_DIGEST_LENGTH*2);
    memcpy(addr_name, char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH), 2*SHA256_DIGEST_LENGTH);

    msg_p->type = KEY_X;
    dest_key = load_pubkey_ring(addr_name, ctx_p);
    cipher_sz = RSA_size(dest_key);
    temp_cipher = malloc(cipher_sz + 1);

    content_len = cipher_sz + SHA256_DIGEST_LENGTH;
    msg_p->content = malloc(content_len);

    RAND_bytes(seed, AES_KEY_SZ/8); // generate random number to be used as seed for AES key
    aes_key = SHA256(seed, AES_KEY_SZ/8, NULL); // generate AES key
    // Encrypt certificate key (RSA)       
    if ((cipher_len = public_encrypt(aes_key, SHA256_DIGEST_LENGTH, dest_key, temp_cipher)) == -1){ // encrypt rsa key
        printf("Error: message encryption failed\n");
        return -1;
    }

    printf("aes key encrypted\n");
                   
    //store IV to buffer

    unsigned char temp_iv[AES_KEY_SZ/8];
    unsigned char iv[IV_SZ/8];
    unsigned char *temp_hash;

    RAND_bytes(temp_iv, IV_SZ/8);
    temp_hash = SHA256(temp_iv, IV_SZ/8, NULL);
    memcpy(iv, temp_hash, IV_SZ/8);

    msg_p->sz = cipher_len + IV_SZ/8;
    printf("msg_p->sz = %d\n", msg_p->sz);
    memcpy(msg_p->content, temp_cipher, cipher_len);
    memcpy(msg_p->content+cipher_len, temp_hash, IV_SZ/8);

    // create message signature

    unsigned char *sig_hash = malloc(SHA256_DIGEST_LENGTH);
    sig_hash = SHA256(msg_p->content, msg_p->sz, NULL);
    msg_p->signature = malloc(RSA_size(ctx_p->rsa_priv_key));
    if ((msg_p->sig_len = private_encrypt(sig_hash, SHA256_DIGEST_LENGTH, ctx_p->rsa_priv_key, msg_p->signature)) == -1){
        printf("Error: signature encryption failed\n");
        return -1;
    } 
}

int parse_pubkey_x_buf(msg *msg_p, ctx *ctx_p, unsigned char *buf, int buf_len){ // extract RSA public key data from recieved buffer
    int m = sizeof(MAGIC) + sizeof(msg_p->type);
    if (buf_len >= (2 * sizeof(MAGIC) + 2 * SHA256_DIGEST_LENGTH + sizeof(msg_p->timestamp) + sizeof(msg_p->sz))){ // Handle certificate message
        m += SHA256_DIGEST_LENGTH;
        memcpy(msg_p->send_addr, &buf[m], SHA256_DIGEST_LENGTH);
        m += SHA256_DIGEST_LENGTH;
        m += sizeof(msg_p->timestamp);
        msg_p->sz = *(unsigned int*)(&buf[m]);
        m += sizeof(msg_p->sz);
        if (msg_p->sz > (buf_len - (SHA256_DIGEST_LENGTH * 2 + sizeof(MAGIC) + sizeof(msg_p->timestamp) + sizeof(msg_p->sz)))){
            printf("Error: cert size too large\n");
            return -1;
        }
        msg_p->content = malloc(msg_p->sz);
        memcpy(msg_p->content, &buf[m], msg_p->sz);
        store_pubkey(msg_p->content, msg_p->sz, char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH));
        load_pubkey(char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH), ctx_p);
        for (int i = 0; i < ctx_p->pubkey_count; i++){
            for (int k = 0; k < SHA256_DIGEST_LENGTH*2; k++){
                putchar(ctx_p->pubkeys[i].addr[k]);
            }
        }
    } else {
        printf("Error: Incorrect key formatting\n");
        return -1;
    }                    
    printf("certifcate recvd\n");
}

int parse_key_x_buf(msg *msg_p, ctx* ctx_p, unsigned char *buf, int buf_len){ // extract shared AES key data from recieved buffer // to do: open RSA key from file, malloc temp_aes
    unsigned char *temp_aes_rsa_cipher;
    unsigned char *temp_aes;
    unsigned char *temp_iv;
    unsigned char *addr;
    int m = sizeof(MAGIC) + sizeof(msg_p->type);
    // Handle RSA keypair message
    if (buf_len > (sizeof(MAGIC) + sizeof(msg_p->type) + SHA256_DIGEST_LENGTH * 2 + sizeof(msg_p->timestamp) + sizeof(msg_p->sz) + SHA256_DIGEST_LENGTH + sizeof(MAGIC))){ /// parse encrypted aes key
        m += SHA256_DIGEST_LENGTH;
        memcpy(msg_p->send_addr, &buf[m], SHA256_DIGEST_LENGTH);
        m += SHA256_DIGEST_LENGTH;
        memcpy(&msg_p->timestamp, &buf[m], sizeof(msg_p->timestamp));
        m += sizeof(msg_p->timestamp);
        memcpy(&msg_p->sz, &buf[m], sizeof(msg_p->sz));
        m += sizeof(msg_p->sz);
        printf("in_msg.sz = %d\n", msg_p->sz);
        if ((buf_len - (sizeof(MAGIC) + sizeof(msg_p->type) + SHA256_DIGEST_LENGTH * 2 + sizeof(msg_p->timestamp) + sizeof(msg_p->sz)) < msg_p->sz) || msg_p->sz < SHA256_DIGEST_LENGTH){
            printf("Error: Incorrect message content size\n");
            return -1;
        }
        msg_p->content = malloc(msg_p->sz);
        temp_aes_rsa_cipher = malloc(msg_p->sz-IV_SZ/8);
        temp_iv = malloc(IV_SZ/8);
        temp_aes = malloc(RSA_size(ctx_p->rsa_priv_key));
        memcpy(msg_p->content, &buf[m], msg_p->sz);
        m += msg_p->sz;
        memcpy(&msg_p->sig_len, &buf[m], sizeof(msg_p->sig_len));
        if ((buf_len - (sizeof(MAGIC) + sizeof(msg_p->type) + SHA256_DIGEST_LENGTH * 2 + sizeof(msg_p->timestamp) + sizeof(msg_p->sz) + msg_p->sz + sizeof(msg_p->sig_len)) < msg_p->sig_len)){
            printf("Error: Incorrect message signature size\n");
            return -1;
        }
        m += sizeof(msg_p->sig_len);
        memcpy(msg_p->signature, &buf[m], msg_p->sig_len);

        memcpy(temp_aes_rsa_cipher, msg_p->content, msg_p->sz-IV_SZ/8);
        memcpy(temp_iv, msg_p->content + (msg_p->sz-IV_SZ/8), IV_SZ/8);
    } else {
        printf("buf_len to small\n");
        return -1;
    }
    printf("parsed rsa keypair\n");
    addr = malloc(2*SHA256_DIGEST_LENGTH);
    memcpy(addr, char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH), 2*SHA256_DIGEST_LENGTH);

    ctx_p->aes_keys = realloc(ctx_p->aes_keys, (ctx_p->keyring_sz+1)*sizeof(aes_keyring));
    ctx_p->keyring_sz += 1;
    if (private_decrypt(temp_aes_rsa_cipher, msg_p->sz-IV_SZ/8, ctx_p->rsa_priv_key, temp_aes) != AES_KEY_SZ/8){
        printf("Incorrect AES size\n");
        return -1;
    }
    memcpy(ctx_p->aes_keys[ctx_p->keyring_sz-1].key, temp_aes, AES_KEY_SZ/8);
    memcpy(ctx_p->aes_keys[ctx_p->keyring_sz-1].key, temp_iv, IV_SZ/8);
    for (int k = 0; k < AES_KEY_SZ/8; k++){
        putchar(ctx_p->aes_keys[ctx_p->keyring_sz-1].key[k]);
    }
    putchar('\n');
}