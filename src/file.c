#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/sha.h>
#include"common.h"


FILE* open_file(char *file){ // open file
    FILE* fp;
    if ((fp = fopen(file, "rb")) == NULL)
        return NULL;

    return fp;
}

int fsize(FILE* fp){ // get size of file
    int sz;
    fseek(fp, 0, SEEK_END);
    sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    return sz;
}

int isfile(unsigned char *fname){ // check if file exists
    FILE *fp;
    if (fp = fopen(fname, "r")){
        fclose(fp);
        return 1;
    }
    return 0;
}
