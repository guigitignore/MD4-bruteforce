#ifndef UTIL_H_INCLUDED
#define UTIL_H_INCLUDED
#include <stdint.h>

#include "config.h"

//functions to convert ascii char into hexa value between 0 and 15 (-1 in case of error)
int hexFromChar(char c){
    if (c>='0' && c<='9'){
        return c-'0';
    }else if (c>='a' && c<='z'){
        return c-'a'+10;
    }else if (c>='A' && c<='Z'){
        return c-'A'+10;
    }
    return -1;
}

// parse hexa string and return array of byte
void* parseDigest(char* argv,uint8_t output[MD4_SIZE]){
    for (int i=0,c,v=0;i<(MD4_SIZE<<1);i++){
        c=hexFromChar(argv[i]);
        if (c==-1) return NULL;
        if (i&0x1) output[i>>1]=v|c;
        else v=c<<4;
    }
    return argv;
}

//character table used in passwords
const char* charTable="abcdefghikjlmnopqrstuvwxyz!\"#$%&";

void getPasswordFromId(uint64_t id,char password[PWD_LEN+1]){
    for (char *end=password+PWD_LEN;password<end;password++){
        *password=charTable[id&0x1f];
        id>>=5;
    }
    *password='\0';
}

// init constants
const uint32_t bits= PWD_LEN << 3;
const uint32_t round2Number=0x5a827999;
const uint32_t round3Number=0x6ed9eba1;

//max id for simd.c and simple.c
#define MAX_ID (1LU << (5*PWD_LEN))-1

//basic transformations used in MD4
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)			(((x) ^ (y)) ^ (z))

#endif