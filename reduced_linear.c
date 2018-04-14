#include "simon.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define SAMPLES	1024
#define REDUCED 4	// ???
#define GETBIT(num, i) (((num) >> (i)) & 01)
#define GETBITMOD(num, i, m) (((num) >> ((i) + m) % m) & 01)

// K ^ P_j ^ P_{15+j} ^ P_{14 + j} = c_j

void gather(int j, uint16_t *plain, uint16_t *cipher, int num_samples){
	float count[2] = {0, 0};

	char guess;
	uint16_t xp, xc, yp, yc;
	for(int i = 0; i < num_samples; i++){
		xp = plain[2 * i];
		xc = cipher[2 * i];
		yp = plain[2 * i + 1];
		yc = cipher[2 * i + 1];
		guess = GETBIT(yc, j) ^ GETBIT(yp, j) ^ GETBITMOD(xp, j - 1, 16) ^ GETBITMOD(xp, j - 2, 16);
		count[guess]++;
	}

	printf("0: %g\n", count[0] / num_samples);
	printf("1: %g\n", count[1] / num_samples);
}

void genPairs(uint16_t *plain, uint16_t *cipher, uint16_t *key, int num_pairs){
	for (int i = 0; i < num_pairs; i++){
		plain[2*i] = cipher[2*i] = rand();
		plain[2*i+1] = cipher[2*i+1] = rand();
		reducedEncrypt(cipher + 2 * i, key, 2, REDUCED);
	}
}

int main(){
	srand(time(NULL));
	uint16_t plain[64], cipher[64];
	uint16_t key[ROUNDS] = {0x1918, 0x1110, 0x0908, 0x0100};

	keyExpansion(key);

	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	genPairs(plain, cipher, key, 32);
	gather(3, plain, cipher, 32);
	gather(8, plain, cipher, 32);
	clock_gettime(CLOCK_MONOTONIC, &end);
	
}