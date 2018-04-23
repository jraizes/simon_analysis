#include "simon.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#define GETBITMOD(num, i, m) (((num) >> ((i) + m) % m) & 01)


/***********************/
/****** Utilities ******/
/***********************/

typedef struct keyprob{
	double prob;
	uint16_t key;
} keyprob;

/* Generates plaintext-ciphertext pairs for a given key */
void genPairs(uint16_t *plain, uint16_t *cipher, uint16_t *key, int num_pairs, int round_num){
	int tmp;
	for (int i = 0; i < num_pairs; i++){
		tmp = rand();	// 32 bits
		plain[2*i] = cipher[2*i] = tmp;	// First half
		plain[2*i+1] = cipher[2*i+1] = tmp >> 16;	// Second half
		reducedEncrypt(cipher + 2 * i, key, 2, round_num);
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

/*****************************/
/****** Attack Outlines ******/
/*****************************/

/* Gathers "evidence" for a given key. */
double gather(char(*eval)(uint16_t*, uint16_t*, uint16_t), uint16_t k, uint16_t *plain, uint16_t *cipher, int num_samples){
	double count = 0;

	// For each plaintext-ciphertext pair, check if it matches the relation given in eval
	for(int i = 0; i < num_samples; i++){
		if (eval(plain + 2*i, cipher + 2*i, k)){
			count++;
		}
	}

	// Return the difference in match percentage from 50%
	return count / num_samples - 0.5;
}

/* Carries out the attack. */
void do_atk(char(*eval)(uint16_t*, uint16_t*, uint16_t), int *key_targs, int key_targ_len, int round_num, int num_samples){
	srand(time(NULL));
	uint16_t *plain, *cipher;
	uint16_t key[ROUNDS];
	plain = calloc(sizeof(uint16_t), num_samples * 2);
	cipher = calloc(sizeof(uint16_t), num_samples * 2);

	// Construct a random key
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

	// Gather evidence for each possible key in the target space
	keyprob *outputs = calloc(1<<key_targ_len, sizeof(keyprob));
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	genPairs(plain, cipher, key, num_samples, round_num);
	uint16_t k = 0;
	for (int i = 0; i < 1<<key_targ_len; i++){
		// Set up the key for this attempt
		for (int j = 0; j < key_targ_len; j++){
			if ((i % (1<<j)) == 0 && i != 0){	// If its that bit's turn to flip, flip it
				k ^= 1 << key_targs[j];
			}
		}

		outputs[i].key = k;
		outputs[i].prob = fabs(gather(eval, k, plain, cipher, num_samples));	// We only care about magnitude of deviation from 50%
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

/*
 * A 6 round attack based on a 3 round linear characteristic with bias 2^-8 (?)
 */

#define TARGS1		(int[4]){6, 8, 13, 15}
#define	TARGLEN1	4
#define SAMPLES1	(1<<20)
#define ROUNDS1		6

char eval1(uint16_t *plain, uint16_t *cipher, uint16_t key){
	uint16_t xp = plain[0];
	uint16_t xc = cipher[0];
	uint16_t yp = plain[1];
	uint16_t yc = cipher[1];
	uint16_t zeros = 0;


	// Do a partial decryption
	R(&key, &yc, &xc);
	R(&zeros, &yc, &xc);	// Strip F off the other side - key doesn't matter

	char lhs = GETBITMOD(yc, 0, 16) ^ GETBITMOD(yc, -2, 16);
	char rhs = GETBITMOD(yp, 0, 16) ^ GETBITMOD(yp, -6, 16) ^ GETBITMOD(xp, -3, 16)
			 ^ GETBITMOD(xp, -4, 16) ^ GETBITMOD(xp, -7, 16) ^ GETBITMOD(xp, -8, 16);

	return lhs == rhs;
}


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
	R(&key, &yc, &xc);
	R(&zeros, &yc, &xc);	// Strip F off the other side - key doesn't matter

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
	R(&key, &yc, &xc);
	R(&zeros, &yc, &xc);	// Strip F off the other side - key doesn't matter

	char lhs = GETBITMOD(yc, 0, 16);
	char rhs = GETBITMOD(yp, 0, 16) ^ GETBITMOD(yp, -4, 16)
			^ GETBITMOD(xp, -1, 16) ^ GETBITMOD(xp, -6, 16);

	return lhs == rhs;
}

/****** *****/

int main(){
	//void do_atk(char(*eval)(uint16_t*, uint16_t*, uint16_t), int *key_targs, int key_targ_len, int round_num, int num_samples){
	
	do_atk(eval1, TARGS1, TARGLEN1, ROUNDS1, SAMPLES1);
	// do_atk(eval3, TARGS3, TARGLEN3, ROUNDS3, SAMPLES3);
}