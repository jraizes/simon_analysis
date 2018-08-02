#include "simon.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

/***********************/
/****** Utilities ******/
/***********************/

#define CONST32(L, R)	0x##R##L 	// Mildly confusing but it makes things match the stuff in the papers...
#define SWAP(a, b)	{a^=b; b^=a; a^=b;}
#define GETBIT(num, i) (((num) >> (i)) & 01)
#define GETBITMOD(num, i, m) (((num) >> ((i) + m) % m) & 01)

typedef struct keyprob{
	double prob;
	uint16_t key[ROUNDS];
} keyprob;

typedef struct key_iter{
	uint16_t key[ROUNDS];	// ROUNDS is max # of rounds for simon 32/64
	int *bits[ROUNDS];
	int bitslen[ROUNDS], totallen, count;
}key_iter;

void del_key_iter(key_iter *it){
	for (int i = 0; i < ROUNDS; i++){
		if (it->bitslen[i] != 0){
			free(it->bits[i]);
		}
	}
	free(it);
}

void print_key(key_iter *it){
	int started = 0;
	for (int i = ROUNDS-1; i >=0; i--){
		if (it->bitslen[i]){
			if (!started){
				printf("0x%04x", it->key[i]);
				started = 1;
			} else{
				printf(" %04x", it->key[i]);
			}
		}
	}

	if (!started){
		printf("0x0000");
	}
}

// For converting a count to a bit-skipped count (ex: 11 -> 101 if we skip bit 1)
int skipcount(int count, int *bits, int bitslen){
	int ret = 0;
	for (int i = 0; i < bitslen; i++){
		ret |= GETBIT(count, i) << bits[i];
	}
	return ret;
}

char increment(key_iter *it){
	it->count++;
	if (it->count >= 1<<(it->totallen)){
		return 0;
	} else{
		int reduced = it->count;
		int i = 0;

		// Find the bucket it belongs in
		while (i < ROUNDS && reduced % (1<<(it->bitslen[i])) == 0){
			it->key[i] = 0;
			reduced >>= it->bitslen[i];
			i++;
		}

		if (i < ROUNDS){	// Sanity check
			it->key[i] = skipcount(reduced, it->bits[i], it->bitslen[i]);
			return 1;
		} else{
			printf("Error incrementing. Check key_iter setup.\n");
			return 0;
		}
	}
}

void print_time_dif(struct timespec start, struct timespec end){
	long seconds = end.tv_sec - start.tv_sec;
	long nsecs = end.tv_nsec - start.tv_nsec;
	if (nsecs < 0){
		seconds--;
		nsecs += 1e9;
	}

	printf("Time: %li.%li seconds\n", seconds, nsecs);
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
uint16_t L_DIFF, R_DIFF;
double RAND;

/* Generates plaintext-ciphertext pairs for a given key */
void gen_pairs(uint16_t *plain, uint16_t *cipher, uint16_t *key, int num_samples, int round_num){
	int tmp, sample;
	for (int i = 0; i < num_samples; i++){
		sample = i * 4;

		tmp = rand();	// 32 bits
		plain[sample] = cipher[sample] = tmp;	// First half
		plain[sample+1] = cipher[sample+1] = tmp >> 16;	// Second half
		reducedEncrypt(cipher + sample, key, 2, round_num);

		// Copy and differentiate
		plain[sample+2] = cipher[sample+2] = plain[sample] ^ L_DIFF;
		plain[sample+3] = cipher[sample+3] = plain[sample+1] ^ R_DIFF;
		reducedEncrypt(cipher + sample + 2, key, 2, round_num);
	}
}

/* Gathers "evidence" for a given key guess. */
double gather(char(*eval)(uint16_t*, uint16_t*, uint16_t*), uint16_t* k, uint16_t *plain, uint16_t *cipher, int num_samples){
	double count = 0;

	// For each plaintext-ciphertext pair, check if it matches the relation given in eval
	for(int i = 0; i < num_samples; i++){
		if (eval(plain + 4*i, cipher + 4*i, k)){
			count++;
		}
	}

	return count / num_samples;
}

/* Carries out the attack. */
void do_atk(char(*eval)(uint16_t*, uint16_t*, uint16_t*), key_iter *it, int round_num, int num_samples){
	srand(time(NULL));
	uint16_t *plain, *cipher;
	uint16_t key[ROUNDS];
	plain = calloc(sizeof(uint16_t), num_samples * 4);
	cipher = calloc(sizeof(uint16_t), num_samples * 4);

	// Construct a random key
	key[0] = rand();
	key[1] = rand();
	key[2] = rand();
	key[3] = rand();
	keyExpansion(key);

	uint16_t target_mask;
	printf("Expected winner: 0x");
	for (int i = ROUNDS - 1; i >= 0; i--){
		target_mask = 0;
		for (int j = 0; j < it->bitslen[i]; j++){
			target_mask |= 1<<(it->bits[i][j]);
		}
		if (target_mask){
			printf("%04x ", key[i] & target_mask);
		}
	}
	printf("\n\n");

	// Gather evidence for each possible key in the target space
	keyprob *outputs = calloc(1<<(it->totallen), sizeof(keyprob));
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	gen_pairs(plain, cipher, key, num_samples, round_num);
	int i = 0;
	do{
		memcpy(&(outputs[i].key), it->key, ROUNDS * sizeof(uint16_t));
		outputs[i].prob = gather(eval, it->key, plain, cipher, num_samples);
		
		i++;
	} while(increment(it) != 0);
	printf("\n");
	clock_gettime(CLOCK_MONOTONIC, &end);

	qsort(outputs, 1<<(it->totallen), sizeof(keyprob), compare);
	int num_to_print = (10 > 1<<(it->totallen)) ? 1<<(it->totallen) : 10;
	for (int i = 0; i < num_to_print; i++){
		memcpy(it->key, outputs[i].key, ROUNDS * sizeof(uint16_t));
		print_key(it);
		printf(": %f\n", outputs[i].prob);
	}
	printf("\n");

	memcpy(it->key, outputs[0].key, ROUNDS * sizeof(uint16_t));
	printf("Most likely subkey: ");
	print_key(it);

	printf("\n");
	print_time_dif(start, end);

	free(plain);
	free(cipher);
	free(outputs);
}


/****** Attacks ******/
#define SET_ATK(X)	char(*eval)(uint16_t*, uint16_t*, uint16_t*) = eval_##X;	\
					int num_samples = SAMPLES_##X; 								\
					int rounds = ROUNDS_##X; 									\
					key_iter *it = init_##X();									\
					L_DIFF = L_DIFF_##X;										\
					R_DIFF = R_DIFF_##X;										

/*
 * Each attack X MUST provide the following:
 *		- char eval_X(uint16_t*, uint16_t*, uint16_t*)
 *		- key_iter *init_X()
 *		- global variable or #define SAMPLES_X
 *		- global variable or #define ROUNDS_X
 * 		- global variable or #define L_DIFF_X
 * 		- global variable or #define R_DIFF_X
 */

/*
 * A 5 round attack based on a 3 round linear differential characteristic
 */

#define SAMPLES_1	(1<<10)
#define ROUNDS_1	5
#define L_DIFF_1	0
#define R_DIFF_1	0x40	// 6

char eval_1(uint16_t *plain, uint16_t *cipher, uint16_t* key){
	uint16_t *Rp = plain;
	uint16_t *Rc = cipher;
	uint16_t *Lp = plain + 1;
	uint16_t *Lc = cipher + 1;

	uint16_t *Rp_flip = plain + 2;
	uint16_t *Rc_flip = cipher + 2;
	uint16_t *Lp_flip = plain + 3;
	uint16_t *Lc_flip = cipher + 3;

	uint16_t zeros = 0;

	uint32_t tmpRc = *((uint32_t*)Rc);
	uint32_t tmpRc_flip = *((uint32_t*)Rc_flip);
	// Do a partial decryption
	R(key + 4, Lc, Rc);
	R(&zeros, Lc, Rc);

	// Same thing
	R(key + 4, Lc_flip, Rc_flip);
	R(&zeros, Lc_flip, Rc_flip);

	uint32_t expected = CONST32(0440, 0100);	// L 6 and 10, R 8
	uint32_t actual = *((uint32_t*)Rc) ^ *((uint32_t*)Rc_flip);

	*((uint32_t*)Rc) = tmpRc;
	*((uint32_t*)Rc_flip) = tmpRc_flip;
	return actual == expected;
}

key_iter *init_1(){
	key_iter *ret = calloc(1, sizeof(key_iter));

	ret->bits[4] = calloc(16, sizeof(int));
	ret->bits[4][0] = 3;
	ret->bits[4][1] = 13;
	ret->bits[4][2] = 15;
	ret->bits[4][3] = 1;
	ret->bitslen[4] = 4;

	ret->totallen = 4;
	return ret;
}



/************/

int main(){
	SET_ATK(1);

	do_atk(eval, it, rounds, num_samples);
	del_key_iter(it);
}