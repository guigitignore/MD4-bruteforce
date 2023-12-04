#include "../include/config.h"

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long int uint64_t;

void * memset( void * pointer, int value, size_t count ){
  for (uint8_t *start=pointer,*end=start+count;start<end;start++){
    *start=value;
  }
  return pointer;
}


int memcmp(void * pointer1,void * pointer2, size_t size ){
	for (void *end=pointer1+size;pointer1<end;pointer1++,pointer2++){
		if (*(uint8_t*)pointer1!=*(uint8_t*)pointer2) return -1;
	}
	return 0;
}

void * memcpy( void * destination,void * source, size_t size ){
	void *dst=destination,*end=dst+size;

	while (dst<end){
		*(uint8_t*)dst++=*(uint8_t*)source++;
	}
	return destination;
}

#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)			(((x) ^ (y)) ^ (z))
#define H2(x, y, z)			((x) ^ ((y) ^ (z)))

#define STEP(f, a, b, c, d, x, s) \
	(a) += f((b), (c), (d)) + (x); \
	(a) = (((a) << (s)) | ((a) >> (32 - (s))));

#define MY_SET(index) (*(uint32_t *)(password+(index<<2)))
#define MY_CAST(ptr) ((uint32_t*)(ptr))

void prepareMD4(char password[64]){
	uint64_t used=PWD_LEN;
	password[used] = 0x80;
	memset(password+used+1, 0, 56-used);
	used<<=3;

	*(uint64_t*)(password+56)=used;
}

void computeMD4(uint8_t result[16],const char password[64]){
	uint32_t a= 0x67452301;
	uint32_t b= 0xefcdab89;
	uint32_t c= 0x98badcfe;
	uint32_t d = 0x10325476;

	uint32_t* base=(uint32_t*)password;

	for (uint32_t* end=(uint32_t*)(password+64);base<end;){
		STEP(F, a, b, c, d,*base++, 3)
		STEP(F, d, a, b, c,*base++, 7)
		STEP(F, c, d, a, b,*base++, 11)
		STEP(F, b, c, d, a,*base++, 19)
	}

	for (uint32_t *ptr=(uint32_t*)password,*end=ptr+4;ptr<end;ptr++){
		base=ptr;
		STEP(G, a, b, c, d, *base + 0x5a827999, 3)
		base+=4;
		STEP(G, d, a, b, c, *base + 0x5a827999, 5)
		base+=4;
		STEP(G, c, d, a, b, *base + 0x5a827999, 9)
		base+=4;
		STEP(G, b, c, d, a, *base + 0x5a827999, 13)
	}



	STEP(H, a, b, c, d, MY_SET(0) + 0x6ed9eba1, 3)
	STEP(H2, d, a, b, c, MY_SET(8) + 0x6ed9eba1, 9)
	STEP(H, c, d, a, b, MY_SET(4) + 0x6ed9eba1, 11)
	STEP(H2, b, c, d, a, MY_SET(12) + 0x6ed9eba1, 15)
	STEP(H, a, b, c, d, MY_SET(2) + 0x6ed9eba1, 3)
	STEP(H2, d, a, b, c, MY_SET(10) + 0x6ed9eba1, 9)
	STEP(H, c, d, a, b, MY_SET(6) + 0x6ed9eba1, 11)
	STEP(H2, b, c, d, a, MY_SET(14) + 0x6ed9eba1, 15)
	STEP(H, a, b, c, d, MY_SET(1) + 0x6ed9eba1, 3)
	STEP(H2, d, a, b, c, MY_SET(9) + 0x6ed9eba1, 9)
	STEP(H, c, d, a, b, MY_SET(5) + 0x6ed9eba1, 11)
	STEP(H2, b, c, d, a, MY_SET(13) + 0x6ed9eba1, 15)
	STEP(H, a, b, c, d, MY_SET(3) + 0x6ed9eba1, 3)
	STEP(H2, d, a, b, c, MY_SET(11) + 0x6ed9eba1, 9)
	STEP(H, c, d, a, b, MY_SET(7) + 0x6ed9eba1, 11)
	STEP(H2, b, c, d, a, MY_SET(15) + 0x6ed9eba1, 15)

	*(uint32_t*)(result)=0x67452301 + a;
	*(uint32_t*)(result+4)=0xefcdab89 + b;
	*(uint32_t*)(result+8)=0x98badcfe +c;
	*(uint32_t*)(result+12)=0x10325476 + d;

}

#define MAX_ITER (1 << ((PWD_LEN-3)*5))

void genPassword(char password[PWD_LEN],char table[32],uint64_t it){
	for (int i=3;i<PWD_LEN;i++){
		password[i]=table[it&0x1f];
		it>>=5;
	}
}

__global static bool hasBeenFound=false;


__kernel void md4_crack(__global const unsigned int *target, __global unsigned char *solution) {
	// Get the index of the current element to be processed
	int id = get_global_id(0);

	char chartable[32];

	for (int i=0;i<26;i++) chartable[i]='a'+i;
	for (int i=26;i<32;i++) chartable[i]='!'+i;

	char buffer[64];
	uint8_t res[16];
	
	buffer[0]=id%26+'a';
	id/=26;
	buffer[1]=id%26+'a';
	id/=26;

	buffer[2]=chartable[id];
	uint64_t it=0;

	prepareMD4(buffer);
	size_t tested = 0;

	do {
		genPassword(buffer,chartable,it);
		computeMD4(res,buffer);

		tested++;
		it++;
		if (memcmp((void*)res, (void*)target, 16) == 0) {
			hasBeenFound=true;
			buffer[PWD_LEN] = 0;
			memcpy(solution,buffer,PWD_LEN+1);
			printf("found: %s, after %ld tries\n", buffer, tested);
			
			return;
		}
	} while (!hasBeenFound && it<MAX_ITER);


}