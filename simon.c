#include "simon.h"

// Simon 32/64
#define WORD_SIZE	16
#define KEY_WORDS	4
#define Z0			0b01100111000011010100100010111110110011100001101010010001011111

#define ROTL(x, i)	(((x) << (i)) | ((x) >> (WORD_SIZE - (i))))
#define ROTR(x, i)	(((x) >> (i)) | ((x) << (WORD_SIZE - (i))))
#define SWAP(x, y)	{(x) ^= (y); (y) ^= (x); (x) ^= (y);}
#define GETBIT(num, i) (((num) >> (i)) & 01)

// uint64_t z[4] = {11111010001001010110000111001101111101000100101011000011100110,
// 10001110111110010011000010110101000111011111001001100001011010,
// 10101111011100000011010010011000101000010001111110010110110011,
// 11011011101011000110010111100000010010001010011100110100001111,
// 11010001111001101011011000100000010111000011001010010011101111}

// Reversed version of the above
// uint64_t z[4] = {0b01100111000011010100100010111110110011100001101010010001011111,
// 				0b01011010000110010011111011100010101101000011001001111101110001, 
// 				0b11001101101001111110001000010100011001001011000000111011110101,
// 				0b11110000101100111001010001001000000111101001100011010111011011,
// 				0b11110111001001010011000011101000000100011011010110011110001011}

// A single round on a single block
void R(uint16_t *k, uint16_t *x, uint16_t *y){
	uint16_t tmp = *x;
	*x = *y ^ (ROTL(*x, 1) & ROTL(*x, 8)) ^ ROTL(*x, 2) ^ *k;
	*y = tmp;
}

// void Rinv(uint64_t* k, uint64_t* x, uint16_t* y);

// Expands a 64 bit key
void keyExpansion(uint16_t* k){
	// Reverse the key
	SWAP(k[0], k[3]);
	SWAP(k[1], k[2]);

	uint16_t tmp;
	for (int round = KEY_WORDS; round < ROUNDS; round++){
		tmp = ROTR(k[round - 1], 3);
		tmp ^= k[round - 3];
		tmp ^= ROTR(tmp, 1);
		k[round] = ~k[round - KEY_WORDS] ^ tmp ^ GETBIT(Z0, round - KEY_WORDS) ^ 3;	// No need for mod 62 in Simon 32/64
	}
}

// Encrypts a series of blocks. Assumes padding.
void encrypt(uint16_t* plaintext, uint16_t* key, int len){
	for(int block = 0; block < len; block += 2){
		for (int round = 0; round < ROUNDS; round++){
			R(key + round, plaintext + block, plaintext + block + 1);
		}
	}
}

// Decrypts a series of blocks
void decrypt(uint16_t* ciphertext, uint16_t* key, int len){
	for(int block = 0; block < len; block += 2){
		for (int round = ROUNDS - 1; round >= 0; round--){
			R(key + round, ciphertext + block + 1, ciphertext + block);	// Reversing key and words inverts it
		}
	}
}

// Encrypts a series of blocks. Assumes padding.
void reducedEncrypt(uint16_t* plaintext, uint16_t* key, int len, int rounds){
	for(int block = 0; block < len; block += 2){
		for (int round = 0; round < rounds; round++){
			R(key + round, plaintext + block, plaintext + block + 1);
		}
	}
}

// Decrypts a series of blocks. Reduced to 2 rounds
void reducedDecrypt(uint16_t* ciphertext, uint16_t* key, int len, int rounds){
	for(int block = 0; block < len; block += 2){
		for (int round = rounds - 1; round >= 0; round--){
			R(key + round, ciphertext + block + 1, ciphertext + block);	// Reversing key and words inverts it
		}
	}
}