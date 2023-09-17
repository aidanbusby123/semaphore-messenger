#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<openssl/sha.h>
#include<openssl/rand.h>
#include"common.h"

int format_txt_msg(msg *msg_p, ctx *ctx_p){ // format plaintext message
    unsigned char temp_iv[IV_SZ/8];
    unsigned char iv[IV_SZ/8];
    int len;
    int cipher_len;
    unsigned char *key;
    unsigned char *cipher;
    unsigned char *temp_hash = malloc(SHA256_DIGEST_LENGTH);
    unsigned char *sig_hash = malloc(SHA256_DIGEST_LENGTH);

    cipher_len = msg_p->sz + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    cipher = malloc(cipher_len);

    RAND_bytes(temp_iv, IV_SZ/8);
    temp_hash = SHA256(temp_iv, IV_SZ/8, NULL);
    memcpy(iv, temp_hash, IV_SZ/8);

    if ((key = load_key_ring(char_to_hex(msg_p->recv_addr, SHA256_DIGEST_LENGTH), ctx_p)) == NULL){
        printf("Error: format_txt_msg: unable to load key\n");
        return -1;
    }

    if ((cipher_len = encrypt(msg_p->content, msg_p->sz, key, iv, cipher)) < 0){
        printf("Error: format_txt_msg: unable to encrypt message contents\n");
        return -1;
    }
    len = cipher_len + IV_SZ/8;
    // create message signature hash

    sig_hash = SHA256(msg_p->content, msg_p->sz, NULL);
    msg_p->signature = malloc(RSA_size(ctx_p->rsa_priv_key));
    if ((msg_p->sig_len = private_encrypt(sig_hash, SHA256_DIGEST_LENGTH, ctx_p->rsa_priv_key, msg_p->signature)) == -1){
        printf("Error: format_txt_msg: signature encryption failed\n");
        return -1;
    }
    msg_p->content = malloc(len);
    memcpy(msg_p->content, cipher, cipher_len);
    memcpy(msg_p->content+cipher_len, iv, IV_SZ/8);

    msg_p->sz = len;
}

int format_pubkey_x_msg(msg *msg_p, ctx *ctx_p, unsigned char *buf){ // format message to send RSA key data
    int m = sizeof(msg_p->type) + SHA256_DIGEST_LENGTH;
    unsigned int content_len;
    int cipher_sz = strlen(ctx_p->rsa_pub_key_s);
    msg_p->type = PUBKEY_X;
    msg_p->sz = cipher_sz;
    msg_p->content = malloc(msg_p->sz);
    memcpy(msg_p->content, ctx_p->rsa_pub_key_s, msg_p->sz);

    memcpy(msg_p->recv_addr, &buf[m], SHA256_DIGEST_LENGTH); // set destination address
    m += SHA256_DIGEST_LENGTH;
    memcpy(msg_p->send_addr, ctx_p->addr, SHA256_DIGEST_LENGTH);
                    
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
    unsigned char *seed = malloc(SHA256_DIGEST_LENGTH);
    unsigned char *addr_name;

    addr_name = malloc(SHA256_DIGEST_LENGTH*2);
    memcpy(addr_name, char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH), 2*SHA256_DIGEST_LENGTH);
    
    memcpy(msg_p->recv_addr, msg_p->send_addr, SHA256_DIGEST_LENGTH);
    memcpy(msg_p->send_addr, ctx_p->addr, SHA256_DIGEST_LENGTH);

    msg_p->type = KEY_X;
    dest_key = load_pubkey_ring(addr_name, ctx_p);
    cipher_sz = RSA_size(dest_key);
    temp_cipher = malloc(cipher_sz + 1);

    content_len = cipher_sz;
    msg_p->content = malloc(content_len);

    RAND_bytes(seed, AES_KEY_SZ/8); // generate random number to be used as seed for AES key
    aes_key = SHA256(seed, AES_KEY_SZ/8, NULL); // generate AES key
    // Encrypt certificate key (RSA)       
    if ((cipher_len = public_encrypt(aes_key, SHA256_DIGEST_LENGTH, dest_key, temp_cipher)) == -1){ // encrypt rsa key
        printf("Error: message encryption failed\n");
        return -1;
    }

    memcpy(msg_p->content, temp_cipher, cipher_len);
    msg_p->sz = cipher_len;

    store_key(msg_p->content, msg_p->sz, char_to_hex(msg_p->recv_addr, SHA256_DIGEST_LENGTH));
    load_key(char_to_hex(msg_p->recv_addr, SHA256_DIGEST_LENGTH), ctx_p);
                   
    // create message signature

    unsigned char *sig_hash = malloc(SHA256_DIGEST_LENGTH);
    sig_hash = SHA256(msg_p->content, msg_p->sz, NULL);
    msg_p->signature = malloc(RSA_size(ctx_p->rsa_priv_key));
    if ((msg_p->sig_len = private_encrypt(sig_hash, SHA256_DIGEST_LENGTH, ctx_p->rsa_priv_key, msg_p->signature)) == -1){
        printf("Error: signature encryption failed\n");
        return -1;
    } 
}

int format_con_msg(msg *msg_p, ctx *ctx_p){
    FILE* log_fp;
    unsigned char log_fname[256] = {0};
    memcpy(msg_p->send_addr, ctx_p->addr, SHA256_DIGEST_LENGTH);
    msg_p->timestamp = (unsigned int)time(NULL);

    strcpy(log_fname, getcwd(NULL, sizeof(log_fname)));
    strcat(log_fname, "/messages/");
    strcat(log_fname, "log");

    log_fp = fopen(log_fname, "rb");
    
    if (log_fp == NULL || fsize(log_fp) < (sizeof(int) + 4*SHA256_DIGEST_LENGTH)){
        msg_p->sz = 0;
        msg_p->content = NULL;
    } else {
        log_fp = fopen(log_fname, "rb");
        msg_p->sz = sizeof(int);
        msg_p->content = malloc(msg_p->sz);

        fseek(log_fp, -1*(sizeof(int) + 4*SHA256_DIGEST_LENGTH), SEEK_END);
        if (fread(msg_p->content, sizeof(int), 1, log_fp) != 1){
            printf("Error: format_con_msg: unable to read timestamp from log\n");
        }
        fclose(log_fp);
    }
    msg_p->signature = malloc(SHA256_DIGEST_LENGTH);
    msg_p->signature = SHA256(msg_p->content, msg_p->sz, NULL);
    msg_p->sig_len = SHA256_DIGEST_LENGTH;
}

int parse_ui_txt_msg(msg *msg_p, ctx *ctx_p, unsigned char *buf){
    int m = sizeof(msg_p->type);
    memcpy(msg_p->send_addr, ctx_p->addr, SHA256_DIGEST_LENGTH);
    memcpy(msg_p->recv_addr, &buf[m], SHA256_DIGEST_LENGTH);
    m += SHA256_DIGEST_LENGTH;
    msg_p->timestamp = *(unsigned int*)(&buf[m]);
    m += sizeof(msg_p->timestamp);
    msg_p->sz = *(unsigned int *)(&buf[m]);
    m += sizeof(msg_p->sz);
    
    msg_p->content = malloc(msg_p->sz);
    memcpy(msg_p->content, &buf[m], msg_p->sz);

    msg_p->signature = malloc(SHA256_DIGEST_LENGTH);
    msg_p->signature = SHA256(msg_p->content, msg_p->sz, NULL);
    msg_p->sig_len = SHA256_DIGEST_LENGTH;
}

int parse_txt_msg(msg *msg_p, ctx *ctx_p, unsigned char *buf, int buf_len){ // parse text message
    unsigned char iv[IV_SZ/8];
    int cipher_len;
    unsigned char *cipher;
    unsigned char *temp;
    unsigned char *key;
    int m = sizeof(msg_p->type);
    m += SHA256_DIGEST_LENGTH;
    memcpy(msg_p->send_addr, &buf[m], SHA256_DIGEST_LENGTH);
    m += SHA256_DIGEST_LENGTH;
    msg_p->timestamp = *(unsigned int*)&buf[m];
    m += sizeof(msg_p->timestamp);
    msg_p->sz = *(unsigned int*)&buf[m];
    m += sizeof(msg_p->sz);
    if (msg_p->sz > (buf_len - (SHA256_DIGEST_LENGTH * 2 + sizeof(msg_p->timestamp) + sizeof(msg_p->sz)))){
        printf("Error: parse_txt_msg: msg size too large\n");
        return -1;
    }
    cipher_len = msg_p->sz - IV_SZ/8;
    cipher = malloc(cipher_len);

    memcpy(cipher, &buf[m], cipher_len);
    m += cipher_len;
    memcpy(iv, &buf[m], IV_SZ/8);
    m += IV_SZ/8;
    msg_p->sig_len = *(unsigned int*)(&buf[m]);
    m += sizeof(msg_p->sig_len);
    msg_p->signature = malloc(msg_p->sig_len);
    memcpy(msg_p->signature, &buf[m], msg_p->sig_len);

    if ((key = load_key_ring(char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH), ctx_p)) == NULL){
        printf("Error: parse_txt_msg: unable to load key\n");
        return -1;
    }

    temp = malloc(cipher_len);

    if ((msg_p->sz = decrypt(cipher, cipher_len, key, iv, temp)) < 0){
        printf("Error: parse_txt_msg: unable to decrypt message contents\n");
        return -1;
    }

    msg_p->content = malloc(msg_p->sz);
    memcpy(msg_p->content, temp, msg_p->sz);
}

int parse_pubkey_x_buf(msg *msg_p, ctx *ctx_p, unsigned char *buf, int buf_len){ // extract RSA public key data from recieved buffer
    int m = sizeof(msg_p->type);
    if (buf_len >= (2 * SHA256_DIGEST_LENGTH + sizeof(msg_p->timestamp) + sizeof(msg_p->sz))){ // Handle certificate message
        m += SHA256_DIGEST_LENGTH;
        memcpy(msg_p->send_addr, &buf[m], SHA256_DIGEST_LENGTH);
        m += SHA256_DIGEST_LENGTH;
        m += sizeof(msg_p->timestamp);
        msg_p->sz = *(unsigned int*)(&buf[m]);
        m += sizeof(msg_p->sz);
        if (msg_p->sz > (buf_len - (SHA256_DIGEST_LENGTH * 2 + sizeof(TX_START) + sizeof(msg_p->timestamp) + sizeof(msg_p->sz)))){
            printf("Error: cert size too large\n");
            return -1;
        }
        msg_p->content = malloc(msg_p->sz);
        memcpy(msg_p->content, &buf[m], msg_p->sz);
        store_pubkey(msg_p->content, msg_p->sz, char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH));
        load_pubkey(char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH), ctx_p);
    } else {
        printf("Error: Incorrect key formatting\n");
        return -1;
    }                    
}

int parse_key_x_buf(msg *msg_p, ctx* ctx_p, unsigned char *buf, int buf_len){ // extract shared AES key data from recieved buffer
    unsigned char *temp_aes_rsa_cipher;
    unsigned char *temp_aes;
    unsigned char *addr;
    int m = sizeof(msg_p->type);
    // Handle RSA keypair message
    if (buf_len > sizeof(msg_p->type) + SHA256_DIGEST_LENGTH * 2 + sizeof(msg_p->timestamp) + sizeof(msg_p->sz) + SHA256_DIGEST_LENGTH){ /// parse encrypted aes key
        m += SHA256_DIGEST_LENGTH;
        memcpy(msg_p->send_addr, &buf[m], SHA256_DIGEST_LENGTH);
        m += SHA256_DIGEST_LENGTH;
        memcpy(&msg_p->timestamp, &buf[m], sizeof(msg_p->timestamp));
        m += sizeof(msg_p->timestamp);
        memcpy(&msg_p->sz, &buf[m], sizeof(msg_p->sz));
        m += sizeof(msg_p->sz);
        if ((buf_len - (sizeof(TX_START) + sizeof(msg_p->type) + SHA256_DIGEST_LENGTH * 2 + sizeof(msg_p->timestamp) + sizeof(msg_p->sz)) < msg_p->sz) || msg_p->sz < SHA256_DIGEST_LENGTH){
            printf("Error: Incorrect message content size\n");
            return -1;
        }
        msg_p->content = malloc(msg_p->sz);
        temp_aes_rsa_cipher = malloc(msg_p->sz);
        temp_aes = malloc(RSA_size(ctx_p->rsa_priv_key));
        memcpy(msg_p->content, &buf[m], msg_p->sz);
        m += msg_p->sz;
        memcpy(&msg_p->sig_len, &buf[m], sizeof(msg_p->sig_len));
        if ((buf_len - (sizeof(msg_p->type) + SHA256_DIGEST_LENGTH * 2 + sizeof(msg_p->timestamp) + sizeof(msg_p->sz) + msg_p->sz + sizeof(msg_p->sig_len)) < msg_p->sig_len)){
            printf("Error: Incorrect message signature size\n");
            return -1;
        }
        m += sizeof(msg_p->sig_len);
        memcpy(msg_p->signature, &buf[m], msg_p->sig_len);

        memcpy(temp_aes_rsa_cipher, msg_p->content, msg_p->sz);
    } else {
        printf("buf_len to small\n");
        return -1;
    }
    addr = malloc(2*SHA256_DIGEST_LENGTH);
    memcpy(addr, char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH), 2*SHA256_DIGEST_LENGTH);

    ctx_p->aes_keys = realloc(ctx_p->aes_keys, (ctx_p->keyring_sz+1)*sizeof(aes_keyring));
    ctx_p->keyring_sz += 1;
    if (private_decrypt(temp_aes_rsa_cipher, msg_p->sz, ctx_p->rsa_priv_key, temp_aes) != AES_KEY_SZ/8){
        printf("Incorrect AES size\n");
        return -1;
    }
    memcpy(ctx_p->aes_keys[ctx_p->keyring_sz-1].key, temp_aes, AES_KEY_SZ/8);
    store_key(ctx_p->aes_keys[ctx_p->keyring_sz-1].key, AES_KEY_SZ/8, char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH));
}

int store_txt_msg(msg *msg_p, ctx *ctx_p, unsigned char *addr){
    FILE *fp;
    FILE *hash_fp;
    unsigned char *buf;
    unsigned char *msg_buf;
    unsigned char *raw_msg_buf;
    int buf_len;
    int msg_buf_len;
    int raw_msg_buf_len;
    unsigned char *name = malloc(2*SHA256_DIGEST_LENGTH+1);
    unsigned char fname[256] = {0};


    memcpy(name, addr, SHA256_DIGEST_LENGTH*2);
    name[SHA256_DIGEST_LENGTH*2] = 0;

    strcpy(fname, getcwd(NULL, sizeof(fname)));
    strcat(fname, "/messages/");
    strcat(fname, name);

    fp = fopen(fname, "ab");

    raw_msg_buf_len = 2*SHA256_DIGEST_LENGTH + sizeof(msg_p->timestamp) + sizeof(msg_p->sz) + msg_p->sz;
    raw_msg_buf = malloc(raw_msg_buf_len);
    memcpy(raw_msg_buf, msg_p->recv_addr, SHA256_DIGEST_LENGTH);
    memcpy(raw_msg_buf+SHA256_DIGEST_LENGTH, msg_p->send_addr, SHA256_DIGEST_LENGTH);
    memcpy(raw_msg_buf+2*SHA256_DIGEST_LENGTH, &msg_p->timestamp, sizeof(msg_p->timestamp));
    memcpy(raw_msg_buf+(2*SHA256_DIGEST_LENGTH)+sizeof(msg_p->timestamp), &msg_p->sz, sizeof(msg_p->sz));
    memcpy(raw_msg_buf+2*SHA256_DIGEST_LENGTH+sizeof(msg_p->timestamp)+sizeof(msg_p->sz), msg_p->content, msg_p->sz);

    if ((msg_buf_len = b64_encode(raw_msg_buf, raw_msg_buf_len, &msg_buf)) < 0){
        printf("Error: store_txt_msg: unable to encode message buf in base64\n");
    }
    buf_len = sizeof(TX_START) + msg_buf_len + sizeof(TX_END);
    buf = malloc(buf_len);
    memcpy(buf, TX_START, sizeof(TX_START));
    memcpy(buf+sizeof(TX_START), msg_buf, msg_buf_len);
    memcpy(buf+sizeof(TX_START)+msg_buf_len, TX_END, sizeof(TX_END));

    if (fwrite(buf, 1, buf_len, fp) < buf_len){
        printf("Error: store_txt_msg: unable to write msg to file\n");
    }
    fclose(fp);

    if (store_txt_msg_log(msg_p, ctx_p, addr) == -1){
        printf("Error: store_txt_msg: store_txt_msg_hash\n");
    }
}

int store_txt_msg_log(msg *msg_p, ctx *ctx_p, unsigned char *addr){
    FILE *fp;
    RSA* pubkey;
    unsigned char fname[256] = {0};
    unsigned char *signature_s;
    unsigned char *name;
    unsigned char *bin_hash;
    unsigned char *hash;
    unsigned char *content;
    int bin_hash_len;
    int hash_len;
    int content_len;

    signature_s = malloc(msg_p->sig_len+1);
    memcpy(signature_s, msg_p->signature, msg_p->sig_len);
    signature_s[msg_p->sig_len] = 0;

    name = malloc(2*SHA256_DIGEST_LENGTH+1);
    memcpy(name, addr, 2*SHA256_DIGEST_LENGTH);
    name[2*SHA256_DIGEST_LENGTH] = 0;

    strcpy(fname, getcwd(NULL, sizeof(fname)));
    strcat(fname, "/messages/");
    strcat(fname, "log");

    if ((pubkey = load_pubkey_ring(name, ctx_p)) == NULL){
        printf("Error: store_txt_msg_hash: unable to find sender RSA pubkey\n");
        return -1;
    }
    
    bin_hash = malloc(RSA_size(pubkey));

    if ((bin_hash_len = public_decrypt(msg_p->signature, msg_p->sig_len, pubkey, bin_hash)) == -1){
        printf("Error: store_txt_msg_hash: unable to decode message signature\n");
        return -1;
    }

    hash_len = 2*SHA256_DIGEST_LENGTH;
    
    hash = char_to_hex(bin_hash, bin_hash_len);

    content_len = sizeof(unsigned int) + 2*SHA256_DIGEST_LENGTH + 2*SHA256_DIGEST_LENGTH;
    content = malloc(content_len);

    memcpy(content, &msg_p->timestamp, sizeof(msg_p->timestamp));
    memcpy(content + sizeof(msg_p->timestamp), char_to_hex(msg_p->send_addr, SHA256_DIGEST_LENGTH), 2*SHA256_DIGEST_LENGTH);
    memcpy(content + sizeof(msg_p->timestamp) + 2*SHA256_DIGEST_LENGTH, hash, hash_len);

    fp = fopen(fname, "ab");

    if (fwrite(content, 1, content_len, fp) != content_len){
        printf("Error: store_txt_msg_hash: unable to write message hash to file\n");
        return -1;
    }
    fputc('\n', fp);
    fclose(fp);
}