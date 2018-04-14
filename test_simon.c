#include "simon.h"

#include <stdio.h>
#include <stdint.h>

int main(){
	uint16_t key[ROUNDS] = {0x1918, 0x1110, 0x0908, 0x0100};
	uint16_t plain[2] = {0x6565, 0x6877};
	uint16_t cipher[2] = {0xc69b, 0xe9bb};

	printf("Plaintext: %x %x\n", plain[0], plain[1]);
	// printf("Ciphertext: %x %x \n", cipher[0], cipher[1]);

	keyExpansion(key);
	// encrypt(plain, key, 2);
	// decrypt(cipher, key, 2);
	reducedEncrypt(plain, key, 2);

	// printf("Plaintext: %x %x\n", cipher[0], cipher[1]);
	printf("Ciphertext: %x %x \n", plain[0], plain[1]);
}