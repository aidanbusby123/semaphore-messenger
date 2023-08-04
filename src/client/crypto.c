#include<stdio.h>
#include<string.h>
#include<dirent.h>
#include<unistd.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include"common.h"

const int padding = RSA_PKCS1_PADDING;

// AES encryption
int encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *iv, unsigned char *cipher){
    EVP_CIPHER_CTX *evp_ctx;
    int len;
    int cipher_len;

    if ((evp_ctx = EVP_CIPHER_CTX_new()) < 0){
        printf("Error: encrypt: EVP_CIPHER_CTX_new\n");
    }
    if ((EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(), NULL, key, iv)) < 0){
        printf("Error: encrypt: EVP_EncryptInit\n");
    }
    if (EVP_EncryptUpdate(evp_ctx, cipher, &len, data, data_len) < 0){
        printf("Error: encrypt: EVP_EncryptUpdate\n");
    }
    cipher_len = len;
    if (EVP_EncryptFinal_ex(evp_ctx, cipher+cipher_len, &len) < 0){
        printf("Error: encrypt: EVP_EncryptFinal_ex\n");
    }
    cipher_len += len;
    EVP_CIPHER_CTX_free(evp_ctx);
    return cipher_len;
}
// AES decryption
int decrypt(unsigned char *cipher, int cipher_len, unsigned char *key, unsigned char *iv, unsigned char *data){
    EVP_CIPHER_CTX *evp_ctx;
    int len;
    int data_len;

    if ((evp_ctx = EVP_CIPHER_CTX_new()) < 0){
        printf("Error: decrypt: EVP_CIPHER_CTX_new\n");
    }
    if (EVP_DecryptInit_ex(evp_ctx, EVP_aes_256_cbc(), NULL, key, iv) < 0){
        printf("Error: decrypt: EVP_DecryptInit_ex\n");
    }
    if (EVP_DecryptUpdate(evp_ctx, data, &len, cipher, cipher_len) < 0){
        printf("Error: decrypt: EVP_DecryptUpdate\n");
    }
    data_len = len;
    if (EVP_DecryptFinal_ex(evp_ctx, data+data_len, &len) < 0){
        printf("Error: decrypt: EVP_DecryptFinal_ex\n");
    }
    data_len += len;
    EVP_CIPHER_CTX_free(evp_ctx);
    return data_len;
}

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

int public_encrypt(unsigned char * data,int data_len, RSA *rsa, unsigned char *encrypted){
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    if (result == -1){
        printf("%s", ERR_error_string(ERR_get_error(), NULL));
    }
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len, RSA *rsa, unsigned char *decrypted){
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    if (result == -1){
        printf("%s", ERR_error_string(ERR_get_error(), NULL));
    }
    return result;
}
int private_encrypt(unsigned char * data,int data_len, RSA *rsa, unsigned char *encrypted){
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    if (result == -1){
        printf("%s", ERR_error_string(ERR_get_error(), NULL));
    }
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len, RSA *rsa, unsigned char *decrypted){
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    if (result == -1){
        printf("%s", ERR_error_string(ERR_get_error(), NULL));
    }
    return result;
}

int store_pubkey(unsigned char *data, int data_len, unsigned char *name){
    FILE *fp;
    unsigned char fname[256] = {0};
    char *keyname = malloc(2*SHA256_DIGEST_LENGTH + strlen(".pem") + 1);
    memcpy(keyname, name, 2*SHA256_DIGEST_LENGTH);
    memcpy(keyname+2*SHA256_DIGEST_LENGTH, ".pem", strlen(".pem"));
    keyname[2*SHA256_DIGEST_LENGTH + strlen(".pem")] = 0;
    strcpy(fname, getcwd(NULL, sizeof(fname)));
    strcat(fname, "/pubkeys/");
    strcat(fname, keyname);
    fp = fopen(fname, "wb");
    if (fwrite(data, sizeof(unsigned char), data_len, fp) < data_len){
        printf("Error: pubkey write failed\n");
        return -1;
    }
    fclose(fp);
    return 0;
}

unsigned char* load_key_ring(unsigned char *name, ctx *ctx_p){
    for (int i = 0; i < ctx_p->keyring_sz; i++){
        if (strncmp(name, ctx_p->aes_keys[i].addr, sizeof(ctx_p->aes_keys->addr)) == 0){
            return ctx_p->aes_keys[i].key;
        }
    }
    printf("Error: load_key_ring\n");
    return NULL;
}

RSA* load_pubkey_ring(unsigned char *name, ctx *ctx_p){
    for (int i = 0; i < ctx_p->pubkey_count; i++){
        if (strncmp(name, ctx_p->pubkeys[i].addr, sizeof(ctx_p->pubkeys->addr)) == 0){
            return ctx_p->pubkeys[i].pubkey;
        }
    }
    printf("Error: unable to load pubkey\n");
    return NULL;
}

int load_pubkeys(ctx *ctx_p){ // load RSA public keys from PEM files, store in keyring
    DIR *dir;
    struct dirent *en;
    FILE *fp;
    unsigned char *keyname;
    unsigned char fname[256] = {0};
    int sz;
    unsigned char *data;
    RSA *rsa;
    int k = 0;

    keyname = malloc(2*SHA256_DIGEST_LENGTH + strlen(".pem") + 1);
    dir = opendir("pubkeys");
    if (dir){
        while ((en = readdir(dir)) != NULL){
            if (strlen(en->d_name) == 2*SHA256_DIGEST_LENGTH + strlen(".pem")){
                strcpy(fname, getcwd(NULL, sizeof(fname)));
                strcat(fname, "/pubkeys/");
                strcat(fname, en->d_name);
                if ((fp = fopen(fname, "rb")) == NULL){
                    printf("Error: failed to open pubkey files\n");
                    return -1;
                }
                sz = fsize(fp);
                data = malloc(sz + 1);
                if (fread(data, sizeof(unsigned char), fsize(fp), fp) < sz){
                    printf("Error: pubkey read failed\n");
                    return -1;
                }
                data[sz] = 0;
                if ((rsa = createRSA(data, PUBLIC)) == NULL){
                    printf("Error: load_pubkeys: unable to create RSA\n");
                    return -1;
                }
                ctx_p->pubkeys = realloc(ctx_p->pubkeys, (ctx_p->pubkey_count+1)*sizeof(struct pubkey_ring));
                ctx_p->pubkeys[ctx_p->pubkey_count].pubkey = rsa;
                memcpy(ctx_p->pubkeys[ctx_p->pubkey_count].addr, en->d_name, 2*SHA256_DIGEST_LENGTH);
                ctx_p->pubkey_count++;
                bzero(fname, sizeof(fname));
            } else 
                continue;
        }
    } else  
        return -1;
    return 0;
}

int load_pubkey(unsigned char *name, ctx *ctx_p){
    unsigned char fname[256] = {0};
    unsigned char *data;
    int sz;
    FILE *fp;
    RSA *rsa;
    
    strcpy(fname, getcwd(NULL, sizeof(fname)));
    strcat(fname, "/pubkeys/");
    strncat(fname, name, 2*SHA256_DIGEST_LENGTH);
    strcat(fname, ".pem");
    if ((fp = fopen(fname, "rb")) == NULL){
        printf("Error: unable to open specified RSA pem file\n");
        return -1;
    }
    sz = fsize(fp);
    data = malloc(sz + 1);
    if (fread(data, sizeof(unsigned char), fsize(fp), fp) < sz){
        printf("Error: pubkey read failed\n");
        return -1;
    }
    data[sz] = 0;
    rsa = createRSA(data, PUBLIC);
    ctx_p->pubkeys = realloc(ctx_p->pubkeys, ctx_p->pubkey_count*sizeof(pubkey_ring) + sizeof(pubkey_ring));
    ctx_p->pubkeys[ctx_p->pubkey_count].pubkey = rsa;
    memcpy(ctx_p->pubkeys[ctx_p->pubkey_count].addr, name, 2*SHA256_DIGEST_LENGTH);
    ctx_p->pubkey_count++;
}

int store_key(unsigned char *data, int data_len, unsigned char *name){
    char *keyname = malloc(2*SHA256_DIGEST_LENGTH + strlen(".key") + 1);
    unsigned char fname[256] = {0};
    FILE *fp;
    memcpy(keyname, name, 2*SHA256_DIGEST_LENGTH);
    memcpy(keyname+2*SHA256_DIGEST_LENGTH, ".key", strlen(".key"));
    keyname[2*SHA256_DIGEST_LENGTH + strlen(".key")] = 0;
    strcpy(fname, getcwd(NULL, sizeof(fname)));
    strcat(fname, "/keys/");
    strcat(fname, keyname);
    fp = fopen(fname, "wb");
    if (fwrite(data, sizeof(unsigned char), data_len, fp) < data_len){
        printf("key write error\n");
        return -1;
    }
    fclose(fp);
    return 0;    
}

int load_keys(ctx *ctx_p){
    DIR *dir;
    struct dirent *en;
    FILE *fp;
    unsigned char *keyname;
    unsigned char fname[256] = {0};
    int sz;
    unsigned char *data;
    int k = 0;

    keyname = malloc(2*SHA256_DIGEST_LENGTH + strlen(".key") + 1);
    dir = opendir("keys");
    if (dir){
        while ((en = readdir(dir)) != NULL){
            if (strlen(en->d_name) == 2*SHA256_DIGEST_LENGTH + strlen(".pem")){
                strcpy(fname, getcwd(NULL, sizeof(fname)));
                strcat(fname, "/keys/");
                strcat(fname, en->d_name);
                if ((fp = fopen(fname, "rb")) == NULL){
                    printf("Error: failed to open private key files\n");
                    return -1;
                }
                sz = fsize(fp);
                if (sz != AES_KEY_SZ/8){
                    printf("Error: incorrect AES key size\n");
                    return -1;
                }
                data = malloc(sz);
                if (fread(data, sizeof(unsigned char), fsize(fp), fp) < sz){
                    printf("Error: key read failed\n");
                    return -1;
                }

                ctx_p->aes_keys = realloc(ctx_p->aes_keys, (ctx_p->keyring_sz+1)*sizeof(struct aes_keyring));
                memcpy(ctx_p->aes_keys[ctx_p->keyring_sz].key, data, sz);
                memcpy(ctx_p->aes_keys[ctx_p->keyring_sz].addr, en->d_name, 2*SHA256_DIGEST_LENGTH);
                ctx_p->keyring_sz++;
                bzero(fname, sizeof(fname));
            } else 
                continue;
        }
    } else  
        return -1;
    return 0;
}

int load_key(unsigned char *addr, ctx *ctx_p){
    unsigned char *fname;
    unsigned char *data;
    int sz;
    FILE *fp;

    fname = malloc(2*SHA256_DIGEST_LENGTH + strlen(".key") + 1);
    memcpy(fname, addr, 2*SHA256_DIGEST_LENGTH);
    memcpy(fname + 2*SHA256_DIGEST_LENGTH, ".key", strlen(".key") + 1);
    if ((fp = fopen(fname, "rb")) == NULL){
        printf("Error: unable to open specified key file\n");
        return -1;
    }
    sz = fsize(fp);
    data = malloc(sz);
    if (fread(data, sizeof(unsigned char), fsize(fp), fp) < sz){
        printf("Error: key read failed\n");
        return -1;
    }
    ctx_p->aes_keys = realloc(ctx_p->aes_keys, (ctx_p->keyring_sz+1)*sizeof(aes_keyring));
    memcpy(ctx_p->aes_keys[ctx_p->keyring_sz].key, data, sz);
    memcpy(ctx_p->aes_keys[ctx_p->keyring_sz].addr, addr, 2*SHA256_DIGEST_LENGTH);
    ctx_p->keyring_sz++;
}

int pubkey_known(unsigned char *addr){
    unsigned char fname[2*SHA256_DIGEST_LENGTH + strlen(".pem") + 1];
    memcpy(fname, addr, 2*SHA256_DIGEST_LENGTH);
    memcpy(fname+2*SHA256_DIGEST_LENGTH, ".pem", strlen(".pem")+1);
    if (isfile(fname))
        return 1;
    else
        return -1;
}

unsigned char* char_to_hex(unsigned char *s, int len){ // convert bytes to hex representation
    int sz = len;
    unsigned char *hex = malloc(2 * sz + 1);
    for (int i = 0; i < sz; i++){
        hex[2 * i] = ((s[i]/16) >= 10) ? ('a' + s[i]/16 - 10) : (s[i] / 16) + '0';
        hex[2 * i + 1] = ((s[i] - ((s[i]/16) * 16)) >= 10) ? ('a' + (s[i] - ((s[i]/16) * 16)) - 10) : s[i] - (s[i]/16) * 16 + '0';
    }
    return hex;
}
int b64_encoded_size(int inlen){
	int ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}
int b64_decoded_size(unsigned char *in, int in_len){
	int ret;
	int i;

	if (in == NULL)
		return 0;

	ret = in_len / 4 * 3;
	for (i=in_len; i--; i>0) {
		if (in[i] == '=') {
			ret--;
		} else {
			break;
		}
	}

	return ret;
}

int b64_valid_char(unsigned char c){
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c == '+' || c == '/' || c == '=')
		return 1;
	return -1;
}


int b64_encode(unsigned char *in, unsigned long int in_len, unsigned char **out){ // encode in base64
	int out_len;
	int  i;
	int  j;
	int  v;

	if (in == NULL || in_len == 0)
		return 0;

	out_len = b64_encoded_size(in_len);
	(*out) = malloc(out_len);

	for (i=0, j=0; i<in_len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < in_len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < in_len ? v << 8 | in[i+2] : v << 8;

		(*out)[j]   = b64_charset[(v >> 18) & 0x3F];
		(*out)[j+1] = b64_charset[(v >> 12) & 0x3F];
		if (i+1 < in_len) {
			(*out)[j+2] = b64_charset[(v >> 6) & 0x3F];
		} else {
			(*out)[j+2] = '=';
		}
		if (i+2 < in_len) {
			(*out)[j+3] = b64_charset[v & 0x3F];
		} else {
			(*out)[j+3] = '=';
		}
	}

	return out_len;
}
int b64_decode(unsigned char *in, unsigned long int in_len, unsigned char **out){ // decode in base64
	unsigned long int i;
	unsigned long int j;
	int v;
    long int out_len;
    
    out_len = b64_decoded_size(in, in_len);
    *out = malloc(out_len);

	if (in == NULL)
		return -1;

	for (i=0; i<in_len; i++) {
		if (!b64_valid_char(in[i])) {
			return -1;
		}
	}

	for (i=0, j=0; i<in_len; i+=4, j+=3) {
		v = b64_inv[in[i]-43];
		v = (v << 6) | b64_inv[in[i+1]-43];
		v = in[i+2]=='=' ? v << 6 : (v << 6) | b64_inv[in[i+2]-43];
		v = in[i+3]=='=' ? v << 6 : (v << 6) | b64_inv[in[i+3]-43];

		(*out)[j] = (v >> 16) & 0xFF;
		if (in[i+2] != '=')
			(*out)[j+1] = (v >> 8) & 0xFF;
		if (in[i+3] != '=')
			(*out)[j+2] = v & 0xFF;
	}
	return out_len;
}


