// aes_utils.h
#ifndef AES_UTILS_H
#define AES_UTILS_H

void initialize_aes_sbox(uint8_t sbox[256]);


uint32_t RotWord (uint32_t value, unsigned int count);

void SubBytes(uint8_t matrix[4][4], uint8_t sbox[256]);

uint32_t SubWord(uint32_t inputKey, uint8_t sbox[256]);

uint32_t* keyExpansion(uint32_t *ogKey, uint8_t sbox[256]);

void AddKeyHelper(uint8_t state[4][4], uint32_t *hexValue, int start);
#endif