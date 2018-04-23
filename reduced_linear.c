#include "simon.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define SAMPLES	1<<14
#define REDUCED 6 	// 3 rounds + 3 for a key to guess
#define GETBIT(num, i) (((num) >> (i)) & 01)
#define GETBITMOD(num, i, m) (((num) >> ((i) + m) % m) & 01)
#define SWAP(a, b)	{a^=b; b^=a; a^=b;}

/****** Utilities ******/

typedef struct keyprob{
	double prob;
	uint16_t key;
} keyprob;

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

int compare(const void *a,const void *b) {	// For sorting
	keyprob *ka = (keyprob*)a;
	keyprob *kb = (keyprob*)b;

	if (ka->prob < kb->prob){
		return 1;
	} else{
		return -1;
	}
}

/****** Attack Outlines ******/
double gather(char(*eval)(uint16_t*, uint16_t*, uint16_t), uint16_t k, uint16_t *plain, uint16_t *cipher, int num_samples){
	double count = 0;

	for(int i = 0; i < num_samples; i++){
		if (eval(plain + 2*i, cipher + 2*i, k)){
			count++;
		}
	}

	return count / num_samples - 0.5;
}

void do_atk(char(*eval)(uint16_t*, uint16_t*, uint16_t), int *key_targs, int key_targ_len, int round_num, int num_samples){
	srand(time(NULL));
	uint16_t *plain, *cipher;
	uint16_t key[ROUNDS];
	plain = calloc(sizeof(uint16_t), num_samples * 2);
	cipher = calloc(sizeof(uint16_t), num_samples * 2);

	key[0] = rand();
	key[1] = rand();
	key[2] = rand();
	key[3] = rand();
	keyExpansion(key);
	printf("Key for round %d: 0x%04x\n", round_num, key[round_num - 1]);

	uint16_t target_mask = 0;
	for (int i = 0; i < key_targ_len; i++){
		target_mask |= 1 << key_targs[i];
	}
	printf("Expected winner: 0x%04x\n\n", key[round_num - 1] & target_mask);

	keyprob *outputs = calloc(1<<key_targ_len, sizeof(keyprob));
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	genPairs(plain, cipher, key, SAMPLES);
	uint16_t k = 0;
	for (int i = 0; i < 1<<key_targ_len; i++){
		// Set up the key for this attempt
		for (int j = 0; j < key_targ_len; j++){
			// printf("%d %% %d = %d\n", i, 1<<j, i % (1<<j));
			if ((i % (1<<j)) == 0 && i != 0){	// If its that bit's turn to flip, flip it
				// printf("Flipping!\n");
				k ^= 1 << key_targs[j];
			}
		}
		// printf("%04x\n", k);

		outputs[i].key = k;
		outputs[i].prob = fabs(gather(eval, k, plain, cipher, num_samples));
		printf("0x%04x: %f\n", outputs[i].key, outputs[i].prob);
	}
	printf("\n");
	clock_gettime(CLOCK_MONOTONIC, &end);
	printf("\n");


	// Determine the most likely key
	keyprob *winner = outputs + 0;
	for (int i = 0; i < 1<<key_targ_len; i++){
		if (outputs[i].prob > winner->prob){
			winner = outputs + i;
		}
	}
	printf("Most likely subkey: 0x%04x (%f)\n", winner->key, winner->prob);

	printf("\n");
	printTimeDif(start, end);

	// free(plain);
	// free(cipher);
	// free(outputs);
}


// /****** Attacks ******/

// // c_j = y_j ^ y_(j-2) ^ y_(j-4) ^ x_(j-3) ^ x_(j-4) ^ x_(j-5) ^ x_(j-6)
// // err 2^-6 (2^-4?)
// // c_j ^ c_(j-2) = y_j ^ y_(j-6) ^ x_(j-3) ^ x_(j-4) ^ x_(j-7) ^ x(j-8)
// // c_(j-4) ^ c_(j-2) ^ c_j = y_j ^ y_(j-4) ^ y_(j-8) ^ ...

// // c_j = y_j ^ y_(j-4)^ x_(j-6)

// /*
//  * A 6 round attack based on a 3 round linear characteristic with bias ??? TODO
//  */

// char eval1(uint16_t *plain, uint16_t *cipher, uint16_t key){
// 	uint16_t xp = plain[0];
// 	uint16_t xc = cipher[0];
// 	uint16_t yp = plain[1];
// 	uint16_t yc = cipher[1];
// 	uint16_t zeros = 0;


// 	// Do a partial decryption
// 	R(&key, &yc, &xc);	// 6 rounds means feed it in backwards like normal
// 	R(&zeros, &yc, &xc);	// Strip F - key doesn't matter
// 	// printf("key 0x%04x: 0x%04x\n", key, yc);

// 	char lhs = GETBITMOD(yc, 10, 16) ^ GETBITMOD(yc, 10-2, 16);
// 	char rhs = GETBITMOD(yp, 10, 16) ^ GETBITMOD(yp, 10-6, 16) ^ GETBITMOD(xp, 10-3, 16)
// 			 ^ GETBITMOD(xp, 10-4, 16) ^ GETBITMOD(xp, 10-7, 16) ^ GETBITMOD(xp, 10-8, 16);

// 	return lhs == rhs;
// }

// double gather(int j, uint16_t k, uint16_t *plain, uint16_t *cipher, int num_samples){
// 	double count = 0;

// 	uint16_t xp, xc, yp, yc, zeros=0;
// 	char lhs, rhs;
// 	for(int i = 0; i < num_samples; i++){
// 		xp = plain[2 * i];
// 		xc = cipher[2 * i];
// 		yp = plain[2 * i + 1];
// 		yc = cipher[2 * i + 1];

// 		// Do a partial decryption
// 		// printf("	%04x %04x\n", xc, yc);
// 		R(&k, &yc, &xc);	// 6 rounds means feed it in backwards like normal
// 		// printf("%04x %04x\n", xc, yc);
// 		R(&zeros, &yc, &xc);	// Strip F - key doesn't matter
// 		// printf("%04x %04x\n", xc, yc);
// 		// printf("%d, %d\n", GETBIT(yc, j), GETBIT(yc, j-2));

// 		// SWAP(xc, yc);

// 		/* Reminder:	xc, yc  	8458 0542
// 						xc, yc=>	0542 9350 
// 						The part that changes is the "y" portion in the equation */
// 		lhs = GETBITMOD(yc, j, 16) ^ GETBITMOD(yc, j-2, 16);
// 		rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-6, 16) ^ GETBITMOD(xp, j-3, 16)
// 			 ^ GETBITMOD(xp, j-4, 16) ^ GETBITMOD(xp, j-7, 16) ^ GETBITMOD(xp, j-8, 16);
// 		// printf("%d, %d\n", lhs, rhs);
// 		if (lhs == rhs){
// 			count++;
// 		}
// 	}

// 	return count / num_samples - 0.5;
// }

// void attack1(){
// 	srand(time(NULL));
// 	uint16_t *plain, *cipher;
// 	uint16_t key[ROUNDS];
// 	plain = calloc(sizeof(uint16_t), SAMPLES << 1);
// 	cipher = calloc(sizeof(uint16_t), SAMPLES << 1);

// 	key[0] = rand();
// 	key[1] = rand();
// 	key[2] = rand();
// 	key[3] = rand();
// 	keyExpansion(key);
// 	printf("Key for round 6: 0x%04x\n", key[5]);
// 	printf("Expected winner: 0x%04x\n\n", key[5] & 0b1010000101);

// 	keyprob outputs[1<<4];
// 	struct timespec start, end;
// 	clock_gettime(CLOCK_MONOTONIC, &start);
// 	genPairs(plain, cipher, key, SAMPLES);
// 	uint16_t k = 0;
// 	uint target;
// 	for (uint a = 0; a < 2; a++){
// 		k ^= 1;	// bit 0
// 		for (uint b = 0; b < 2; b++){
// 			k ^= 1 << 2;	// bit 2
// 			for (uint c = 0; c < 2; c++){
// 				k ^= 1 << 7;	// bit 7
// 				for (uint d = 0; d < 2; d++){
// 					k ^= 1 << 9;	// bit 9
// 					target = (a) + (b<<1) + (c<<2) + (d<<3);
// 					outputs[target].key = k;
// 					outputs[target].prob = fabs(gather(10, k, plain, cipher, SAMPLES));
// 					printf("0x%04x: %f\n", k, outputs[target].prob);
// 				}
// 			}
// 		}
// 	}
// 	printf("\n");
// 	printf("0x%04x: %f\n", key[5], fabs(gather(4, key[5], plain, cipher, SAMPLES)));
// 	clock_gettime(CLOCK_MONOTONIC, &end);
// 	printf("\n");


// 	// Determine the most likely key
// 	keyprob *winner = outputs + 0;
// 	for (int i = 0; i < 1<<4; i++){
// 		if (outputs[i].prob > winner->prob){
// 			winner = outputs + i;
// 		}
// 	}
// 	printf("Most likely subkey: 0x%04x\n", winner->key);

// 	printf("\n");
// 	printTimeDif(start, end);

// 	free(plain);
// 	free(cipher);
// }


/*
 * A 6 round attack with a 3 round linear characteristic of bias roughly 2^-6
 */
#define TARGS2		(int[2]){8, 15}
#define	TARGLEN2	2
#define SAMPLES2	(1<<14)
#define ROUNDS2		6

char eval2(uint16_t *plain, uint16_t *cipher, uint16_t key){
	uint16_t xp = plain[0];
	uint16_t xc = cipher[0];
	uint16_t yp = plain[1];
	uint16_t yc = cipher[1];
	uint16_t zeros = 0;


	// Do a partial decryption
	R(&key, &yc, &xc);	// 6 rounds means feed it in backwards like normal
	R(&zeros, &yc, &xc);	// Strip F - key doesn't matter
	// printf("key 0x%04x: 0x%04x\n", key, yc);

	char lhs = GETBITMOD(yc, 0, 16);
	char rhs = GETBITMOD(yp, 0, 16) ^ GETBITMOD(yp, -4, 16)
		^ GETBITMOD(xp, 4, 16) ^ GETBITMOD(xp, -6, 16) ^ GETBITMOD(xp, -8, 16);

	return lhs == rhs;
}

/*
 * A 6 round attack with a 3 round linear characteristic of bias roughly 2^-6
 */
#define TARGS3		(int[2]){8, 15}
#define	TARGLEN3	2
#define SAMPLES3	(1<<14)
#define ROUNDS3		6

char eval3(uint16_t *plain, uint16_t *cipher, uint16_t key){
	uint16_t xp = plain[0];
	uint16_t xc = cipher[0];
	uint16_t yp = plain[1];
	uint16_t yc = cipher[1];
	uint16_t zeros = 0;


	// Do a partial decryption
	R(&key, &yc, &xc);	// 6 rounds means feed it in backwards like normal
	R(&zeros, &yc, &xc);	// Strip F - key doesn't matter
	// printf("key 0x%04x: 0x%04x\n", key, yc);

	char lhs = GETBITMOD(yc, 0, 16);
	char rhs = GETBITMOD(yp, 0, 16) ^ GETBITMOD(yp, -4, 16)
			^ GETBITMOD(xp, -1, 16) ^ GETBITMOD(xp, -6, 16);

	return lhs == rhs;
}

// double gather2(int j, uint16_t k, uint16_t *plain, uint16_t *cipher, int num_samples){
// 	double count = 0;

// 	uint16_t xp, xc, yp, yc, zeros=0;
// 	char lhs, rhs;
// 	for(int i = 0; i < num_samples; i++){
// 		xp = plain[2 * i];
// 		xc = cipher[2 * i];
// 		yp = plain[2 * i + 1];
// 		yc = cipher[2 * i + 1];

// 		// Do a partial decryption
// 		// printf("	%04x %04x\n", xc, yc);
// 		R(&k, &yc, &xc);	// 6 rounds means feed it in backwards like normal
// 		// printf("%04x %04x\n", xc, yc);
// 		R(&zeros, &yc, &xc);	// Strip F - key doesn't matter
// 		// printf("%04x %04x\n", xc, yc);
// 		// printf("%d, %d\n", GETBIT(yc, j), GETBIT(yc, j-2));
// 		// printf("key 0x%04x: 0x%04x\n", k, yc);

// 		// SWAP(xc, yc);

// 		/* Reminder:	xc, yc  	8458 0542
// 						xc, yc=>	0542 9350 
// 						The part that changes is the "y" portion in the equation */
// 		lhs = GETBITMOD(yc, j, 16);
// 		// rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-12, 16)
// 		// 		^ GETBITMOD(xp, j-14, 16);
// 		// rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-4, 16) ^ GETBITMOD(yp, j-10, 16) ^ GETBITMOD(xp, j-6, 16);
// 		// rhs = GETBITMOD(xp, j, 16) ^ GETBITMOD(xp, j-6, 16) ^ GETBITMOD(xp, j-12, 16)
// 				// ^ GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j - 4, 16);
// 		// rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-12, 16)
// 		// 		^ GETBITMOD(xp, j, 16) ^ GETBITMOD(xp, j-10, 16);
// 		// rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-12, 16)
// 		// 		^ GETBITMOD(xp, j, 16) ^ GETBITMOD(xp, j-4, 16)
// 		// 		^ GETBITMOD(xp, j-10, 16) ^ GETBITMOD(xp, j-11, 16)
// 		// 		^ GETBITMOD(xp, j-15, 16);
// 		// printf("%d, %d\n", lhs, rhs);

// 		// (y) 10000000 00001000	(x) 00000000 00100001
// 		//weight: 0.012238
// 		// rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-4, 16)
// 		// 		^ GETBITMOD(xp, j-1, 16) ^ GETBITMOD(xp, j-6, 16);

// 		// Bits: (y) 10000000 00001000	(x) 00001000 10100000
// 			// weight: 0.013611
// 		rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-4, 16)
// 				^ GETBITMOD(xp, j+4, 16) ^ GETBITMOD(xp, j-6, 16) ^ GETBITMOD(xp, j-8, 16);

// 			// (y) 10000000 00001000	(x) 10001000 00100000
// 		// rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-4, 16)
// 		// 		^ GETBITMOD(xp, j, 16) ^ GETBITMOD(xp, j+4, 16) ^ GETBITMOD(xp, j-6, 16);

// 		// Bits: (y) 10000000 00001000	(x) 00001000 00110001
// 		// rhs = GETBITMOD(yp, j, 16) ^ GETBITMOD(yp, j-4, 16)
// 		// 		^ GETBITMOD(xp, j-1, 16) ^ GETBITMOD(xp, j-5, 16) ^ GETBITMOD(xp, j-6, 16) ^ GETBITMOD(xp, j+4, 16);

// 		if (lhs == rhs){
// 			count++;
// 		}
// 	}

// 	return count / num_samples - 0.5;
// }

// void attack2(){
// 	srand(time(NULL));
// 	uint16_t *plain, *cipher;
// 	uint16_t key[ROUNDS];
// 	plain = calloc(sizeof(uint16_t), SAMPLES << 1);
// 	cipher = calloc(sizeof(uint16_t), SAMPLES << 1);

// 	key[0] = rand();
// 	key[1] = rand();
// 	key[2] = rand();
// 	key[3] = rand();
// 	keyExpansion(key);
// 	printf("Key for round 6: 0x%04x\n", key[5]);
// 	printf("Expected winner: 0x%04x\n\n", key[5] & 0b1000000100000000);

// 	keyprob outputs[1<<16];
// 	struct timespec start, end;
// 	clock_gettime(CLOCK_MONOTONIC, &start);
// 	genPairs(plain, cipher, key, SAMPLES);
// 	uint16_t k = 0;
// 	uint target;
// 	for (uint a = 0; a < 2; a++){
// 		k ^= 1 << 15;	// bit 15 (0-1)
// 		for (uint b = 0; b < 2; b++){
// 			k ^= 1 << 8;	// bit 8 (0-8)
// 			// for (uint c = 0; c < 2; c++){
// 			// 	k ^= 1 << 14; // bit 8
// 				target = (a) + (b<<1);
// 				outputs[target].key = k;
// 				outputs[target].prob = fabs(gather2(0, k, plain, cipher, SAMPLES));
// 				printf("0x%04x: %f\n", k, outputs[target].prob);
// 			// }
// 		}
// 	}
// 	// for (int i = 0; i < 1<<16; i++){
// 	// 	if (i % 4096 == 0){
// 	// 		printf("%d\n", i);
// 	// 	}
// 	// 	outputs[i].key = i;
// 	// 	outputs[i].prob = fabs(gather2(0, i, plain, cipher, SAMPLES));
// 	// }
// 	printf("\n");
// 	clock_gettime(CLOCK_MONOTONIC, &end);
// 	printf("\n");


// 	// Determine the most likely key
// 	// keyprob *winner = outputs + 0;
// 	// for (int i = 0; i < 1<<2; i++){
// 	// 	if (outputs[i].prob > winner->prob){
// 	// 		winner = outputs + i;
// 	// 	}
// 	// }
// 	// printf("Most likely subkey: 0x%04x\n", winner->key);
	
// 	// qsort(outputs, 1<<16, sizeof(keyprob), compare);
// 	// double last = 0;
// 	// for(int i = 0; i < 10; i++){
// 	// 	if (outputs[i].prob != last){
// 	// 		printf("0x%04x: %f\n", outputs[i].key, outputs[i].prob);
// 	// 		last = outputs[i].prob;
// 	// 	}
// 	// }

// 	// keyprob *winner, tmp;
// 	// for(int i = 0; i < 10; i++){	// A simple partial insertion sort
// 	// 	winner = outputs + i;
// 	// 	for (int j = i; j < 1<<16; j++){
// 	// 		if (outputs[i].prob > winner->prob){
// 	// 			winner = outputs + i;
// 	// 		}
// 	// 	}

// 	// 	// print the winner then swap stuff
// 	// 	printf("0x%04x: %f\n", winner->key, winner->prob);
// 	// 	tmp.key = winner->key;
// 	// 	tmp.prob = winner->prob;
// 	// 	winner->key = outputs[i].key;
// 	// 	winner->prob = outputs[i].prob;
// 	// 	outputs[i].key = tmp.key;
// 	// 	outputs[i].prob = tmp.prob;
// 	// }

// 	keyprob *winner = outputs + 0;
// 	for (int i = 0; i < 1<<2; i++){
// 		if (outputs[i].prob > winner->prob){
// 			winner = outputs + i;
// 		}
// 	}
// 	printf("Winner: 0x%04x (%f)\n", winner->key, winner->prob);

// 	printf("\n");
// 	printTimeDif(start, end);

// 	free(plain);
// 	free(cipher);
// }


/*
 * A 10 round attack with a 7 round linear characteristic of bias roughly 2^-10.
 */

char atk3(){
	return 0;
}


/****** *****/

int main(){
	//void do_atk(char(*eval)(uint16_t*, uint16_t*, uint16_t), int *key_targs, int key_targ_len, int round_num, int num_samples){
	
	do_atk(eval2, TARGS2, TARGLEN2, ROUNDS2, SAMPLES2);
	// do_atk(eval3, TARGS3, TARGLEN3, ROUNDS3, SAMPLES3);
}