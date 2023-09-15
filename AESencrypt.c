#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include "aes_utils.h"

// Number of rounds for AES-128
#define AES_ROUNDS 10



// AES-128 round constants
const uint8_t Rcon[AES_ROUNDS] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};


//Length of the key in 32 bit words
int N = 4;

//Number of round keys needed
int R = 11;

// Function to perform a one-byte left circular shift
uint8_t* RotWord(uint8_t* inputKey) {
    uint8_t tempByte = inputKey[0];
            inputKey[0] = inputKey[1];
            inputKey[1] = inputKey[2];
            inputKey[2] = inputKey[3];
            inputKey[3] = tempByte;
}

//This will apply SubWord to a size 4 array of 1 byte chunks
//This represents basically a single word from the key
//Least horrible way of doing this and kinda safe ig
uint32_t SubWord(uint8_t* inputKey, uint8_t sbox[256]){
    uint32_t result = 0;
    for (int i = 0; i < 4; i++) {
        result |= ((uint32_t)sbox[inputKey[i]]) << (24 - (i*8));
    }
    return result;
}

//This will now perform the whole KeyExpansion using the function defined previously
uint32_t* keyExpansion(uint32_t* ogKey){
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    // Allocate memory for the expanded array
    uint32_t* expandedKey = (uint32_t*)malloc((4*R) * sizeof(uint32_t));
    //Using the rule to fill W_i in expandedKey
    for(int i = 0; i < 4* R - 1; i++){
        if (i < N){
            expandedKey[i] = ogKey[i];
        } else if (i >= N && (i % N == 0 % N)){
            expandedKey[i] = expandedKey[i-N] ^ SubWord(RotWord(expandedKey[i-1]), sbox);
        }

    }
}


int main() {
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    uint8_t word[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t word2[4] = {0x11, 0x22, 0x33, 0x44};
    uint32_t bruh = SubWord(word, sbox);
    RotWord(word2);
    printf("SubWord word: 0x%X\n", bruh);
    printf("RotWord word2: 0x%X%X%X%X\n", word2[0], word2[1], word2[2], word2[3]);
}