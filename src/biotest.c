#include<stdio.h>
#include<openssl/bio.h>
int main(){
    char data[] = "Hello World";
    BIO *mem;
    mem = BIO_new_mem_buf(data, -1);
}