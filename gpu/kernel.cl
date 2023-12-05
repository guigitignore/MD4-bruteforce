#include "../include/config.h"

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long int uint64_t;

#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)			(((x) ^ (y)) ^ (z))

#define SIMPLIFIED_STEP1(f,a,b,c,d)  (a) += f((b), (c), (d))
#define STEP1(f,a,b,c,d,x)           (a) += f((b), (c), (d)) + (x)
#define STEP2(a,s)                   (a) = (((a) << (s)) | ((a) >> (32 - (s))))

#define STEP(f, a, b, c, d, x, s)          STEP1(f,a,b,c,d,x); STEP2(a,s)
#define SIMPLIFIED_STEP(f, a, b, c, d, s)  SIMPLIFIED_STEP1(f,a,b,c,d); STEP2(a,s)

typedef struct{
    uint32_t a,b,c,d;
}md4;

const uint32_t bits= PWD_LEN << 3;
const uint32_t round2Number=0x5a827999;
const uint32_t round3Number=0x6ed9eba1;

const md4 md4Init={
    .a=0x67452301,
    .b=0xefcdab89,
    .c=0x98badcfe,
    .d=0x10325476
};

md4 searchedDigest;

void setSearchedDigest(uint8_t* digest){
    searchedDigest.a=*(uint32_t*)(digest)   -md4Init.a;
    searchedDigest.b=*(uint32_t*)(digest+4) -md4Init.b;
    searchedDigest.c=*(uint32_t*)(digest+8) -md4Init.c;
    searchedDigest.d=*(uint32_t*)(digest+12)-md4Init.d;
}

const char charTable[32]="abcdefghikjlmnopqrstuvwxyz!\"#$%&";

void getPasswordFromId(uint64_t id,char* password){
	for (int i=3;i<PWD_LEN;i++){
		password[i]=charTable[id&0x1f];
		id>>=5;
	}
}

bool searchMD4(uint64_t id,uint32_t initValue){ 
    union{
        uint32_t words[2];
        uint8_t bytes[8];
        uint64_t value;
    }password;

    password.value=initValue;

    for (int i=3;i<PWD_LEN;i++){
        password.bytes[i]=charTable[id&0x1F];
        id>>=5;
    }
    password.bytes[PWD_LEN]=0x80;
    
    
    // md4 simplified algorithm
    md4 digest=md4Init;

    //round 1

    STEP(F, digest.a, digest.b, digest.c, digest.d,password.words[0], 3);
    STEP(F, digest.d, digest.a, digest.b, digest.c,password.words[1], 7);

    for (int i=0;i<3;i++){
        SIMPLIFIED_STEP(F, digest.c, digest.d, digest.a, digest.b, 11);
        SIMPLIFIED_STEP(F, digest.b, digest.c, digest.d, digest.a, 19);
        SIMPLIFIED_STEP(F, digest.a, digest.b, digest.c, digest.d, 3);
        SIMPLIFIED_STEP(F, digest.d, digest.a, digest.b, digest.c, 7);   
    }

    STEP(F, digest.c, digest.d, digest.a, digest.b,bits, 11);
    STEP(F, digest.b, digest.c, digest.d, digest.a,0, 19);

    //round 2
    for (int i=0;i<2;i++){
        STEP(G, digest.a, digest.b, digest.c, digest.d, password.words[i] + round2Number, 3);
        STEP(G, digest.d, digest.a, digest.b, digest.c,  round2Number, 5);
        STEP(G, digest.c, digest.d, digest.a, digest.b,  round2Number, 9);
        STEP(G, digest.b, digest.c, digest.d, digest.a,  round2Number, 13);
    }

    STEP(G, digest.a, digest.b, digest.c, digest.d,  round2Number, 3);
    STEP(G, digest.d, digest.a, digest.b, digest.c,  round2Number, 5);
    STEP(G, digest.c, digest.d, digest.a, digest.b,  round2Number, 9);
    STEP(G, digest.b, digest.c, digest.d, digest.a,  bits + round2Number, 13);

    STEP(G, digest.a, digest.b, digest.c, digest.d,  round2Number, 3);
    STEP(G, digest.d, digest.a, digest.b, digest.c,  round2Number, 5);
    STEP(G, digest.c, digest.d, digest.a, digest.b,  round2Number, 9);
    STEP(G, digest.b, digest.c, digest.d, digest.a,  round2Number, 13);

    //round3

    STEP(H, digest.a, digest.b, digest.c, digest.d, password.words[0] + round3Number, 3);
	STEP(H, digest.d, digest.b, digest.c, digest.a,  round3Number, 9);
	STEP(H, digest.c, digest.d, digest.a, digest.b,  round3Number, 11);
	STEP(H, digest.b, digest.d, digest.a, digest.c,  round3Number, 15);

	STEP(H, digest.a, digest.b, digest.c, digest.d,  round3Number, 3);
	STEP(H, digest.d, digest.b, digest.c, digest.a,  round3Number, 9);
	STEP(H, digest.c, digest.d, digest.a, digest.b,  round3Number, 11);
	STEP(H, digest.b, digest.d, digest.a, digest.c,  bits + round3Number, 15);

    STEP(H, digest.a, digest.b, digest.c, digest.d,  password.words[1] + round3Number, 3);
	STEP(H, digest.d, digest.b, digest.c, digest.a,  round3Number, 9);
	STEP(H, digest.c, digest.d, digest.a, digest.b,  round3Number, 11);
	STEP(H, digest.b, digest.d, digest.a, digest.c,  round3Number, 15);

	STEP(H, digest.a, digest.b, digest.c, digest.d,  round3Number, 3);
	STEP(H, digest.d, digest.b, digest.c, digest.a,  round3Number, 9);
	STEP(H, digest.c, digest.d, digest.a, digest.b,  round3Number, 11);
	STEP(H, digest.b, digest.d, digest.a, digest.c,  round3Number, 15);
    
    return digest.a==searchedDigest.a &&
           digest.b==searchedDigest.b &&
           digest.c==searchedDigest.c &&
           digest.d==searchedDigest.d;
}

__global static bool hasBeenFound=false;

#define MAX_ITER (1 << ((PWD_LEN-3)*5))

__kernel void md4_crack(__global uint8_t *target, __global char *solution) {
	// Get the index of the current element to be processed
	int gid = get_global_id(0);

	uint32_t initValue=0;
	
	initValue|=gid%26+'a';
	gid/=26;
	initValue|=(gid%26+'a')<<8;
	gid/=26;
	initValue|=charTable[gid]<<16;

	setSearchedDigest(target);

	uint64_t id=0;
	size_t tested = 0;
	
	do {
		tested++;
		if (searchMD4(id,initValue)) {
			*(uint32_t*)solution|=initValue;
            getPasswordFromId(id,solution);

            hasBeenFound=true;

            printf("found: \"%s\", after %ld tries\n", solution, tested);
            break;
		}
		id++;
	} while (!hasBeenFound && id<MAX_ITER);
	

}