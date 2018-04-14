# include	<stdint.h>

#define ROUNDS		32

// Simon 32/64
void keyExpansion(uint16_t* k);
void encrypt(uint16_t* plaintext, uint16_t* key, int len);
void decrypt(uint16_t* ciphertext, uint16_t* key, int len);

// Reduced round versions
void reducedEncrypt(uint16_t* plaintext, uint16_t* key, int len, int rounds);
void reducedDecrypt(uint16_t* ciphertext, uint16_t* key, int len, int rounds);

// For partial encryption/decryption
void R(uint16_t *k, uint16_t *x, uint16_t *y);