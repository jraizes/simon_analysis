#include "simon.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define SAMPLES	1<<20
#define REDUCED 6 	// 3 rounds + 3 for a key to guess
#define GETBIT(num, i) (((num) >> (i)) & 01)
#define GETBITMOD(num, i, m) (((num) >> ((i) + m) % m) & 01)
#define SWAP(a, b)	{a^=b; b^=a; a^=b;}

// c_j = y_j ^ y_(j-2) ^ y_(j-4) ^ x_(j-3) ^ x_(j-4) ^ x_(j-5) ^ x_(j-6)
// err 2^-6 (2^-4?)
// c_j ^ c_(j-2) = y_j ^ y_(j-6) ^ x_(j-3) ^ x_(j-4) ^ x_(j-7) ^ x(j-8)
// c_(j-4) ^ c_(j-2) ^ c_j = y_j ^ y_(j-4) ^ y_(j-8) ^ ...

double gather(int j, uint16_t k, uint16_t *plain, uint16_t *cipher, int num_samples){
	double count = 0;

	uint16_t xp, xc, yp, yc, zeros=0;
	char lhs, rhs;
	for(int i = 0; i < num_samples; i++){
		xp = plain[2 * i];
		xc = cipher[2 * i];
		yp = plain[2 * i + 1];
		yc = cipher[2 * i + 1];

		// Do a partial decryption
		// printf("	%04x %04x\n", xc, yc);
		R(&k, &yc, &xc);	// 6 rounds means feed it in backwards like normal
		// printf("%04x %04x\n", xc, yc);
		R(&zeros, &yc, &xc);	// Strip F - key doesn't matter
		// printf("%04x %04x\n", xc, yc);
		// printf("%d, %d\n", GETBIT(yc, j), GETBIT(yc, j-2));

		// SWAP(xc, yc);

		/* Reminder:	xc, yc  	8458 0542
						xc, yc=>	0542 9350 
						The part that changes is the "y" portion in the equation */
		lhs = GETBITMOD(yc, j, 16) ^ GETBITMOD(yc, j-2, 16);
		rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-6, 16) ^ GETBITMOD(xp, j-3, 16)
			 ^ GETBITMOD(xp, j-4, 16) ^ GETBITMOD(xp, j-7, 16) ^ GETBITMOD(xp, j-8, 16);
		// printf("%d, %d\n", lhs, rhs);
		if (lhs == rhs){
			count++;
		}
	}

	return count / num_samples - 0.5;
}

// double gather(int j, uint16_t k, uint16_t *plain, uint16_t *cipher, int num_samples){
// 	double count = 0;

// 	uint16_t xp, xc, yp, yc;
// 	char lhs, rhs;
// 	for(int i = 0; i < num_samples; i++){
// 		xp = plain[2 * i];
// 		xc = cipher[2 * i];
// 		yp = plain[2 * i + 1];
// 		yc = cipher[2 * i + 1];

// 		// Do a partial decryption TODO
// 		R(&k, &yc, &xc);	// 5 rounds means it's on the other side
// 		// printf("%04x %04x\n", xc, yc);
// 		// printf("%d, %d\n", GETBIT(yc, j), GETBIT(yc, j-2));

// 		lhs = GETBIT(yc, j) ^ GETBIT(yc, j-2) ^ GETBIT(yc, j-4);
// 		rhs = GETBIT(yp, j) ^ GETBIT(yp, j-4) ^ GETBIT(yp, j-8) ^ GETBIT(xp, j-3)
// 				^ GETBIT(xp, j-4) ^ GETBIT(xp, j-6) ^ GETBIT(xp, j-9) ^ GETBIT(xp, j-10);
// 		// printf("%d, %d\n", lhs, rhs);
// 		if (lhs == rhs){
// 			count++;
// 		}
// 	}

// 	return count / num_samples - 0.5;
// }

void genPairs(uint16_t *plain, uint16_t *cipher, uint16_t *key, int num_pairs){
	int tmp;
	for (int i = 0; i < num_pairs; i++){
		tmp = rand();	// 32 bits
		plain[2*i] = cipher[2*i] = tmp;	// First half
		plain[2*i+1] = cipher[2*i+1] = tmp >> 16;	// Second half
		reducedEncrypt(cipher + 2 * i, key, 2, REDUCED);
	}
}

void printTimeDif(struct timespec start, struct timespec end){
	long seconds = end.tv_sec - start.tv_sec;
	long nsecs = end.tv_nsec - start.tv_nsec;
	if (nsecs < 0){
		seconds--;
		nsecs += 1e9;
	}

	printf("Time:%li.%li seconds\n", seconds, nsecs);
}

typedef struct keyprob{
	double prob;
	uint16_t key;
} keyprob;

int compare(const void *a,const void *b) {	// For sorting
	keyprob *ka = (keyprob*)a;
	keyprob *kb = (keyprob*)b;

	if (ka->prob < kb->prob){
		return 1;
	} else{
		return -1;
	}
}

int main(){
	srand(time(NULL));
	uint16_t *plain, *cipher;
	uint16_t key[ROUNDS];
	plain = calloc(sizeof(uint16_t), SAMPLES << 1);
	cipher = calloc(sizeof(uint16_t), SAMPLES << 1);

	key[0] = rand();
	key[1] = rand();
	key[2] = rand();
	key[3] = rand();
	keyExpansion(key);
	printf("Key for round 6: 0x%04x\n", key[5]);
	printf("Expected winner: 0x%04x\n\n", key[5] & 0b1010000101);

	keyprob outputs[1<<4];
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	genPairs(plain, cipher, key, SAMPLES);
	uint16_t k = 0;
	uint target;
	for (uint a = 0; a < 2; a++){
		k ^= 1;	// bit 0
		for (uint b = 0; b < 2; b++){
			k ^= 1 << 2;	// bit 2
			for (volatile uint c = 0; c < 2; c++){	// STOP OPTIMIZING c AWAY!!!
				k ^= 1 << 7;	// bit 7
				for (uint d = 0; d < 2; d++){
					k ^= 1 << 9;	// bit 9
					target = (a) + (b<<1) + (c<<2) + (d<<3);
					outputs[target].key = k;
					outputs[target].prob = fabs(gather(10, k, plain, cipher, SAMPLES));
					printf("0x%04x: %f\n", k, outputs[target].prob);
				}
			}
		}
	}
	printf("\n");
	printf("0x%04x: %f\n", key[5], fabs(gather(4, 0xb649, plain, cipher, SAMPLES)));
	clock_gettime(CLOCK_MONOTONIC, &end);
	printf("\n");


	// Determine the most likely key
	keyprob *winner = outputs + 0;
	for (int i = 0; i < 1<<4; i++){
		if (outputs[i].prob > winner->prob){
			winner = outputs + i;
		}
	}
	printf("Most likely subkey: 0x%04x\n", winner->key);

	printf("\n");
	printTimeDif(start, end);

	free(plain);
	free(cipher);
}