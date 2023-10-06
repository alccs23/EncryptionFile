#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <stdint.h>

// Number of rounds for AES-128
#define AES_ROUNDS 10

// Defining the 4x4 state array for bytes
typedef uint8_t Matrix4x4[4][4];

// Function prototypes
void AddRoundKey(uint32_t *roundKeys, uint8_t matrix[4][4]);
void shiftRows(uint8_t state[4][4]);
uint8_t GalMul(uint8_t input, int factor);
void MixColumns(Matrix4x4 state);
void printArray(uint32_t *arr, int size);
void printMatrix(uint8_t (*state)[4]);
void AESencrypt(uint8_t state[4][4], uint32_t* RKeys, uint8_t sbox[256]);
uint32_t hexCharToInt(char c);
void initialize_aes_inverse_sbox(uint8_t inverse_sbox[256]);
void invShiftRows(uint8_t state[4][4]);
uint8_t GalMul1(uint8_t a, uint8_t b);
void InvMixColumns(uint8_t state[4][4]);
void AESDecrypt(uint8_t state[4][4], uint32_t* RKeys, uint8_t inverseSbox[256], uint8_t sbox[256]);


#endif /* AES_ENCRYPTION_H */