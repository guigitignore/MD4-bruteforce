#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdbool.h>

#include "../include/util.h"

#define SIMPLIFIED_STEP1(f,a,b,c,d)  (a) += f((b), (c), (d))
#define STEP1(f,a,b,c,d,x)           (a) += f((b), (c), (d)) + (x)
#define STEP2(a,s)                   (a) = (((a) << (s)) | ((a) >> (32 - (s))))

#define STEP(f, a, b, c, d, x, s)          STEP1(f,a,b,c,d,x); STEP2(a,s)
#define SIMPLIFIED_STEP(f, a, b, c, d, s)  SIMPLIFIED_STEP1(f,a,b,c,d); STEP2(a,s)

typedef struct{
    uint32_t a,b,c,d;
}md4;


const md4 md4Init={
    .a=0x67452301,
    .b=0xefcdab89,
    .c=0x98badcfe,
    .d=0x10325476
};

md4 searchedDigest;

void setSearchedDigest(uint8_t digest[MD4_SIZE]){
    searchedDigest.a=*(uint32_t*)(digest)   -md4Init.a;
    searchedDigest.b=*(uint32_t*)(digest+4) -md4Init.b;
    searchedDigest.c=*(uint32_t*)(digest+8) -md4Init.c;
    searchedDigest.d=*(uint32_t*)(digest+12)-md4Init.d;
}

bool searchMD4(uint64_t id){ 
    union{
        uint32_t words[2];
        uint8_t bytes[8];
        uint64_t value;
    }password;

    password.value=0;

    for (int i=0;i<PWD_LEN;i++){
        password.bytes[i]=charTable[id&0x1F];
        id>>=5;
    }
    password.bytes[PWD_LEN]=0x80;
    
    
    // md4 simplified algorithm
    register md4 digest=md4Init;

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

int main(int argc,char* argv[]){
    char password[PWD_LEN+1];
    uint8_t target[MD4_SIZE];

    if (argc != 2) {
		fprintf(stderr, "Usage: %s HASH\n", argv[0]);
		return -1;
	}
	
    if (parseDigest(argv[1],target)==NULL){
        fprintf(stderr, "Invalid digest\n");
        return -1;
    }
    setSearchedDigest(target);
    
    size_t tested = 0;
	struct timeval tval;
    uint64_t it=0;
	double start;
	double now;

	gettimeofday(&tval, NULL);
	start = tval.tv_sec + tval.tv_usec / 1000000.0;

	do {
		if (searchMD4(it)) {
            getPasswordFromId(it,password);
            printf("found: \"%s\", after %ld tries\n", password, tested);
            return 0;
		}
        tested++;
		if (tested % (1024 * 1024 * 32) == 0) {
            gettimeofday(&tval, NULL);
            now = tval.tv_sec + tval.tv_usec / 1000000.0;
            double speed = tested / (now - start);
            fprintf(stderr, "%.3f M/s\n", speed / 1000000.0);
		}
        it++;
	} while (it<= MAX_ID);
	printf("not found after %ld tries\n", tested);
	return 1;
    
}