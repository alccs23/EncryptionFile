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

//Number of round kets needed
int R = 11;

// Function to perform a one-byte left circular shift
unsigned char RotWord(unsigned char word) {
    return ((word << 1) | (word >> 7)) & 0xFF;
}

//This will apply SubWord to a size 4 array of 1 byte chunks
//This represents basically a single word from the key
//Least horrible way of doing this and kinda safe ig
void SubWord(uint8_t* inputKey){
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    for (int i = 0; i < 4; i++) {
        inputKey[i] = sbox[inputKey[i]];
    }
}

int main() {
    uint8_t word[4] = {0x11, 0x22, 0x33, 0x44};
    SubWord(word);
    printf("Modified word: 0x%X%X%X%X\n", word[0], word[1], word[2], word[3]);
}