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
uint32_t RotWord (uint32_t value, unsigned int count) {
    return value << count | value >> (32 - count);
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
            expandedKey[i] = expandedKey[i-N] ^ SubWord(RotWord(expandedKey[i-1], 8), sbox) ^ Rcon[i/N];
        } else if (i >= N && N > 6 && (i % N == 4 % N)){
            expandedKey[i] = expandedKey[i-N] ^ SubWord(expandedKey[i-1],sbox);
        } else{
            expandedKey[i] = expandedKey[i-N] ^ expandedKey[i-1];
        }
    }
    return expandedKey;
}

//Defining the 4x4 state array for bytes
typedef uint8_t Matrix4x4[4][4];

//This changes the first 
void AddRoundKey(uint32_t* roundKeys, Matrix4x4 matrix){
    for (int j = 0; j < 4; j++){
        uint32_t reconstructedWord = 0;
        for (int i = 0; i < 4; i++) {
            // Extract the current byte (uint8_t) from the ith word of the expanded round key
            uint8_t currentByte = (uint8_t)(roundKeys[j] >> (24 - (i * 8)));

            // Apply bitwise XOR between expaded round key
            currentByte = currentByte ^ matrix[i][j];

            // Reconstruct the uint32_t with the modified byte
            reconstructedWord |= (uint32_t)currentByte << (24 - (i * 8));

        }
        roundKeys[j] = reconstructedWord; 
    }
}

//The subbytes step of AES encryption
//This just modifies the matrix
void SubBytes(Matrix4x4 matrix, uint8_t sbox[256]){
    for (int j = 0; j < 4; j++){
        for (int i = 0; i < 4; i++) {
            matrix[i][j] = sbox[matrix[i][j]];
        }
    }
}
    
//ShiftRows step of AES-128 encrpytion
void shiftRows(Matrix4x4 state) {
    uint8_t temp;

    // Shift the second row one position to the left (circular shift)
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Shift the third row two positions to the left (circular shift)
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Shift the fourth row three positions to the left (circular shift)
    temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

// Function to print a 1D uint32_t array
void printArray(uint32_t* arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%08x ", arr[i]);
    }
    printf("\n");
}

//Nice helper function to visualize state matrix
void printMatrix(Matrix4x4 state){
     for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            // Use %02X to format each element as a two-digit hexadecimal number
            printf("%02X ", state[i][j]);
        }
        printf("\n"); // Start a new line for the next row
    }
}

//Currently this is used for testing purposes.
//This will be used to do all encrpytion later on
int main() {
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    uint32_t word = RotWord(0x11223344, 8);
    uint32_t word2 = SubWord(0x11223344, sbox);
    printf("RotWord word: 0x%X\n", word);
    printf("SubWord word: 0x%X\n", word2);

    uint32_t ogKey[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t* expandedKey = keyExpansion(ogKey);
    printf("Expanded Key:\n");
    printArray(expandedKey, 4 * R);

    Matrix4x4 state = {
        {0x01, 0x02, 0x03, 0x04},
        {0x05, 0x06, 0x07, 0x08},
        {0x09, 0x0A, 0x0B, 0x0C},
        {0x0D, 0x0E, 0x0F, 0x10}
    };
    AddRoundKey(expandedKey, state);
    printf("Expanded Key (AddRoundKey):\n");
    printArray(expandedKey, 4 * R);

    SubBytes(state, sbox);
    printf("SubBytes States:\n");
    printMatrix(state);
    shiftRows(state);
    printf("ShiftRows States:\n");
    printMatrix(state);
    


    free(expandedKey);
    return 0;

    
}