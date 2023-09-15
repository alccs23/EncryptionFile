#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include "aes_utils.h"

// Number of rounds for AES-128
#define AES_ROUNDS 10



// AES-128 round constants
const uint32_t Rcon[AES_ROUNDS+1] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
};

//Length of the key in 32-bit words: 4 words for AES-128
int N = 4;

//Number of round keys needed
int R = 11;

// Function to perform a one-byte left circular shift
uint32_t RotWord (uint32_t value) {
    return value << 8 | value >> (32 - 8);
}

//This will apply SubWord to a size 4 array of 1 byte chunks
//This represents basically a single word from the key
//Least horrible way of doing this and kinda safe ig
uint32_t SubWord(uint32_t inputKey, uint8_t sbox[256]){
   uint32_t reconstructedWord = 0;
    for (int i = 0; i < 4; i++) {
        // Extract the current byte (uint8_t) from the 32-bit word
        uint8_t currentByte = (uint8_t)(inputKey >> (24 - (i * 8)));

        // Apply your function to the current byte
        currentByte = sbox[currentByte];

        // Reconstruct the uint32_t with the modified byte
        reconstructedWord |= (uint32_t)currentByte << (24 - (i * 8));
    }
    return reconstructedWord;
}

//This will now perform the whole KeyExpansion using the function defined previously
//The imput would be an input of 16 bytes since there are 4 32-bit words. 4* 4bytes = 16 bytes
//This will now perform the whole KeyExpansion using the function defined previously
uint32_t* keyExpansion(uint32_t* ogKey){
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    // Allocate memory for the expanded array
    uint32_t* expandedKey = (uint32_t*)malloc(4*R);
    //Using the rule to fill W_i in expandedKey
    for(int i = 0; i < 4* R; i++){
        if (i < N){
            expandedKey[i] = ogKey[i];
        } else if (i >= N && (i % N == 0 % N)){
            expandedKey[i] = expandedKey[i-N] ^ SubWord(RotWord(expandedKey[i-1]), sbox) ^ Rcon[i/N];
        } else if (i >= N && N > 6 && (i % N == 4 % N)){
            expandedKey[i] = expandedKey[i-N] ^ SubWord(expandedKey[i-1],sbox);
        } else{
            expandedKey[i] = expandedKey[i-N] ^ expandedKey[i-1];
        }
    }
    return expandedKey;
}

// Function to print a 1D uint32_t array
void printArray(uint32_t* arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%08x ", arr[i]);
    }
    printf("\n");
}

int main() {
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    uint32_t word = RotWord(0x11223344);
    uint32_t word2 = SubWord(0x11223344, sbox);
    printf("RotWord word: 0x%X\n", word);
    printf("SubWord word: 0x%X\n", word2);

    uint32_t ogKey[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t* expandedKey = keyExpansion(ogKey);
    printf("Expanded Key:\n");
    printArray(expandedKey, 4 * R);
    free(expandedKey);
    return 0;
}