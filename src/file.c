#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"common.h"


FILE* open_file(char *file){
    FILE* fp;
    if ((fp = fopen(file, "rb")) == NULL)
        return NULL;

    return fp;
}
