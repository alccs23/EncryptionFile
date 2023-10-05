#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "aes_utils.h"

#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

// Number of rounds for AES-128
#define AES_ROUNDS 10


// AES-128 round constants
//The index at 0 is a placeholder, because SubWord works an 1 index. The placeholder will never be called
const uint32_t Rcon[AES_ROUNDS+1] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
};

//Length of the key in 32-bit words: 4 words for AES-128
int N = 4;

//Number of round keys needed
int R = 11;

// I got this code from:https://en.wikipedia.org/wiki/Rijndael_S-box#Example_implementation_in_C_language
//In order to avoid having to manually tpye out the s-box for the AES algo

void initialize_aes_sbox(uint8_t sbox[256]) {
	uint8_t p = 1, q = 1;
	
	/* loop invariant: p * q == 1 in the Galois field */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation */
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		sbox[p] = xformed ^ 0x63;
	} while (p != 1);

	/* 0 is a special case since it has no inverse */
	sbox[0] = 0x63;
}

uint32_t RotWord (uint32_t value, unsigned int count) {
    return value << count | value >> (32 - count);
}

void SubBytes(uint8_t matrix[4][4], uint8_t sbox[256]){
    for (int j = 0; j < 4; j++){
        for (int i = 0; i < 4; i++) {
            matrix[i][j] = sbox[matrix[i][j]];
        }
    }
}

//This will apply SubWord to a size 4 array of 1 byte chunks
//This represents basically a single word from the key
uint32_t SubWord(uint32_t inputKey, uint8_t sbox[256]){
   uint32_t reconstructedWord = 0;
    for (int i = 0; i < 4; i++) {
        // Extract the current byte (uint8_t) from the 32-bit word
        uint8_t currentByte = (uint8_t)(inputKey >> (24 - (i * 8)));

        // Apply sbox mapping to the current byte
        currentByte = sbox[currentByte];

        // Reconstruct the uint32_t with the modified byte
        reconstructedWord |= (uint32_t)currentByte << (24 - (i * 8));
    }
    return reconstructedWord;
}

//This will now perform the whole KeyExpansion using the function defined previously
//This generates the round keys
uint32_t* keyExpansion(uint32_t *ogKey, uint8_t sbox[256]) {
    // Allocate memory for the expanded array
    uint32_t *expandedKey = (uint32_t *)malloc(4 * R * sizeof(uint32_t));
    if (expandedKey == NULL) {
        perror("Memory allocation failed");
        exit(1);
    }
    //Using the rule to fill W_i in expandedKey
    for(int i = 0; i < 4* R; i++){
        if (i < N){
            expandedKey[i] = ogKey[i];
        } else if (i >= N && (i % N == 0 % N)){
            expandedKey[i] = expandedKey[i-N] ^ SubWord(RotWord(expandedKey[i-1], 8), sbox) ^ Rcon[i/N];
        } else if (i >= N && N > 6 && (i % N == 4 % N)){
            expandedKey[i] = expandedKey[i-N] ^ SubWord(expandedKey[i-1],sbox);
        } else{
            expandedKey[i] = expandedKey[i-N] ^ expandedKey[i-1];
        }
    }
    return expandedKey;
}

/*This function will be helpful for mixing the key values with the specific state we are working with, very cool code!*/
void AddKeyHelper(uint8_t state[4][4], uint32_t *hexValue, int start){
    for(int i = 0; i < 4; i++){
            // Extract the first 8 bits (bits 31-24)
            uint32_t first8Bits = (hexValue[i+(4*start)] >> 24) & 0xFF;

            // Extract the second 8 bits (bits 23-16)
            uint32_t second8Bits = (hexValue[i+(4*start)] >> 16) & 0xFF;

            // Extract the third 8 bits (bits 15-8)
            uint32_t third8Bits = (hexValue[i+(4*start)] >> 8) & 0xFF;

            // Extract the last 8 bits (bits 7-0)
            uint32_t last8Bits = hexValue[i+ (4*start)] & 0xFF;
            
            state[0][i] =  state[0][i] ^ first8Bits;
            state[1][i] =  state[1][i] ^ second8Bits;
            state[2][i] =  state[2][i] ^ third8Bits;
            state[3][i] =  state[3][i] ^ last8Bits;
    }
}


