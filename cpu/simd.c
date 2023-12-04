#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdbool.h>

#include "../include/util.h"
#include "../include/simd.h"

#define SIMPLIFIED_STEP1(f,a,b,c,d)  (a) =simd_vector_add_epi32((a),f((b), (c), (d))) 
#define STEP1(f,a,b,c,d,x)           (a) =simd_vector_add_epi32((a),simd_vector_add_epi32(f((b), (c), (d)),(x))) 
#define STEP2(a,s)                   (a) = simd_vector_slli_epi32((a) ,(s)) | simd_vector_srli_epi32((a), (32 - (s)))

#define STEP(f, a, b, c, d, x, s)          STEP1(f,a,b,c,d,x); STEP2(a,s)
#define SIMPLIFIED_STEP(f, a, b, c, d, s)  SIMPLIFIED_STEP1(f,a,b,c,d); STEP2(a,s)

typedef struct{
    simd_vector a,b,c,d;
}md4;

md4 md4Init;

void initMD4(){
    md4Init.a=simd_vector_set1_epi32(0x67452301);
    md4Init.b=simd_vector_set1_epi32(0xefcdab89);
    md4Init.c=simd_vector_set1_epi32(0x98badcfe);
    md4Init.d=simd_vector_set1_epi32(0x10325476);
}

md4 searchedDigest;

void setSearchedDigest(uint8_t digest[MD4_SIZE]){
    
    searchedDigest.a=simd_vector_set1_epi32(*(uint32_t*)(digest));
    searchedDigest.b=simd_vector_set1_epi32(*(uint32_t*)(digest+4));
    searchedDigest.c=simd_vector_set1_epi32(*(uint32_t*)(digest+8));
    searchedDigest.d=simd_vector_set1_epi32(*(uint32_t*)(digest+12));

    searchedDigest.a=simd_vector_sub_epi32(searchedDigest.a,md4Init.a);
    searchedDigest.b=simd_vector_sub_epi32(searchedDigest.b,md4Init.b);
    searchedDigest.c=simd_vector_sub_epi32(searchedDigest.c,md4Init.c);
    searchedDigest.d=simd_vector_sub_epi32(searchedDigest.d,md4Init.d);
}

int searchMD4(uint64_t id){ 
    union{
        uint32_t words[2];
        uint8_t bytes[8];
        uint64_t value;
    }password;

    password.value=0;
    uint8_t fid=id&0x1F;

    for (int i=1;i<PWD_LEN;i++){
        id>>=5;
        password.bytes[i]=charTable[id&0x1F];
    }
    password.bytes[PWD_LEN]=0x80;

    simd_vector vpassword[2]={
        #ifdef SIMD_MMX
        _mm_set_pi32(
            password.words[0]|charTable[fid],
            password.words[0]|charTable[fid+1]
        ),
        #elif defined SIMD_SSE
        _mm_set_epi32(
            password.words[0]|charTable[fid],
            password.words[0]|charTable[fid+1],
            password.words[0]|charTable[fid+2],
            password.words[0]|charTable[fid+3]
        ),
        #elif defined SIMD_AVX
        _mm256_set_epi32(
            password.words[0]|charTable[fid],
            password.words[0]|charTable[fid+1],
            password.words[0]|charTable[fid+2],
            password.words[0]|charTable[fid+3],
            password.words[0]|charTable[fid+4],
            password.words[0]|charTable[fid+5],
            password.words[0]|charTable[fid+6],
            password.words[0]|charTable[fid+7]
        ),
        #endif
        simd_vector_set1_epi32(password.words[1])
    };

    register simd_vector vbits=simd_vector_set1_epi32(bits);;
    register simd_vector vRound2Number=simd_vector_set1_epi32(round2Number);
    register simd_vector vRound3Number=simd_vector_set1_epi32(round3Number);
    
    // md4 simplified algorithm
    register md4 digest=md4Init;

    //round 1

    STEP(F, digest.a, digest.b, digest.c, digest.d,vpassword[0], 3);
    STEP(F, digest.d, digest.a, digest.b, digest.c,vpassword[1], 7);

    for (int i=0;i<3;i++){
        SIMPLIFIED_STEP(F, digest.c, digest.d, digest.a, digest.b, 11);
        SIMPLIFIED_STEP(F, digest.b, digest.c, digest.d, digest.a, 19);
        SIMPLIFIED_STEP(F, digest.a, digest.b, digest.c, digest.d, 3);
        SIMPLIFIED_STEP(F, digest.d, digest.a, digest.b, digest.c, 7);   
    }

    STEP(F, digest.c, digest.d, digest.a, digest.b,vbits, 11);
    SIMPLIFIED_STEP(F, digest.b, digest.c, digest.d, digest.a, 19);

    //round 2
    for (int i=0;i<2;i++){
        STEP(G, digest.a, digest.b, digest.c, digest.d, simd_vector_add_epi32(vpassword[i],vRound2Number), 3);
        STEP(G, digest.d, digest.a, digest.b, digest.c,  vRound2Number, 5);
        STEP(G, digest.c, digest.d, digest.a, digest.b,  vRound2Number, 9);
        STEP(G, digest.b, digest.c, digest.d, digest.a,  vRound2Number, 13);
    }

    STEP(G, digest.a, digest.b, digest.c, digest.d,  vRound2Number, 3);
    STEP(G, digest.d, digest.a, digest.b, digest.c,  vRound2Number, 5);
    STEP(G, digest.c, digest.d, digest.a, digest.b,  vRound2Number, 9);
    STEP(G, digest.b, digest.c, digest.d, digest.a,  simd_vector_add_epi32(vbits,vRound2Number), 13);

    STEP(G, digest.a, digest.b, digest.c, digest.d,  vRound2Number, 3);
    STEP(G, digest.d, digest.a, digest.b, digest.c,  vRound2Number, 5);
    STEP(G, digest.c, digest.d, digest.a, digest.b,  vRound2Number, 9);
    STEP(G, digest.b, digest.c, digest.d, digest.a,  vRound2Number, 13);

    //round3

    STEP(H, digest.a, digest.b, digest.c, digest.d, simd_vector_add_epi32(vpassword[0],vRound3Number), 3);
	STEP(H, digest.d, digest.b, digest.c, digest.a,  vRound3Number, 9);
	STEP(H, digest.c, digest.d, digest.a, digest.b,  vRound3Number, 11);
	STEP(H, digest.b, digest.d, digest.a, digest.c,  vRound3Number, 15);

	STEP(H, digest.a, digest.b, digest.c, digest.d,  vRound3Number, 3);
	STEP(H, digest.d, digest.b, digest.c, digest.a,  vRound3Number, 9);
	STEP(H, digest.c, digest.d, digest.a, digest.b,  vRound3Number, 11);
	STEP(H, digest.b, digest.d, digest.a, digest.c,  simd_vector_add_epi32(vbits,vRound3Number), 15);

    STEP(H, digest.a, digest.b, digest.c, digest.d,  simd_vector_add_epi32(vpassword[1],vRound3Number), 3);
	STEP(H, digest.d, digest.b, digest.c, digest.a,  vRound3Number, 9);
	STEP(H, digest.c, digest.d, digest.a, digest.b,  vRound3Number, 11);
	STEP(H, digest.b, digest.d, digest.a, digest.c,  vRound3Number, 15);

	STEP(H, digest.a, digest.b, digest.c, digest.d,  vRound3Number, 3);
	STEP(H, digest.d, digest.b, digest.c, digest.a,  vRound3Number, 9);
	STEP(H, digest.c, digest.d, digest.a, digest.b,  vRound3Number, 11);
	STEP(H, digest.b, digest.d, digest.a, digest.c,  vRound3Number, 15);

    uint32_t cmp=simd_vector_movemask_epi8(
        simd_vector_cmpeq_epi32(digest.a,searchedDigest.a) &
        simd_vector_cmpeq_epi32(digest.b,searchedDigest.b) &
        simd_vector_cmpeq_epi32(digest.c,searchedDigest.c) &
        simd_vector_cmpeq_epi32(digest.d,searchedDigest.d)
    );
    
    
    for (int i=(sizeof(simd_vector)>>2)-1;i>=0;i--){
        if (cmp&0xF) return i;
        cmp>>=4;
    }
    
    return -1;
}

int main(int argc,char* argv[]){
    char password[PWD_LEN+1];
    uint8_t target[MD4_SIZE];

    if (argc != 2) {
		fprintf(stderr, "Usage: %s HASH\n", argv[0]);
		return -1;
	}
    initMD4();

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
    int cmp;

	gettimeofday(&tval, NULL);
	start = tval.tv_sec + tval.tv_usec / 1000000.0;

	do {
        cmp=searchMD4(it);
		if (cmp!=-1) {
            getPasswordFromId(it+cmp,password);
            printf("found: \"%s\", after %ld tries\n", password, tested);
            return 0;
		}
        tested+=(sizeof(simd_vector)>>2);
		if (tested % (1024 * 1024 * 32) == 0) {
            gettimeofday(&tval, NULL);
            now = tval.tv_sec + tval.tv_usec / 1000000.0;
            double speed = tested / (now - start);
            fprintf(stderr, "%.3f M/s\n", speed / 1000000.0);
		}
        it+=(sizeof(simd_vector)>>2);
	} while (it<= MAX_ID);
	printf("not found after %ld tries\n", tested);
	return 1;
    
}