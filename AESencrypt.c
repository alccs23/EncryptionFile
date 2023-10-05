#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "aes_utils.h"

// Number of rounds for AES-128
#define AES_ROUNDS 10

//Defining the 4x4 state array for bytes
typedef uint8_t Matrix4x4[4][4];





//This changes the first 
void AddRoundKey(uint32_t *roundKeys, uint8_t matrix[4][4]){
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


    
//ShiftRows step of AES-128 encrpytion
void shiftRows(uint8_t state[4][4]) {
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

//This implements the galois multiplication needed
//to implement the matrix multiplication of Rijndael MixColumns
uint8_t GalMul(uint8_t input, int factor) {
    uint8_t highBit = (input >> 7) & 1;
    uint8_t temp = input << 1;
    
    if (factor == 3) {
        temp ^= input;
    }
    
    temp ^= highBit * 0x1B;
    
    return temp;
}

//Function that does MixColumns step
void MixColumns(Matrix4x4 state){
    uint8_t temp1;  
    uint8_t temp2;
    uint8_t temp3;
    uint8_t temp4;     
        for(int j = 0; j < 4; j++){
            temp1 = (GalMul(state[0][j],2)) ^ (GalMul(state[1][j],3)) ^ state[2][j] ^ state[3][j];
            temp2 = state[0][j] ^ (GalMul(state[1][j],2)) ^ (GalMul(state[2][j],3)) ^ state[3][j];
            temp3 = state[0][j] ^ state[1][j] ^ (GalMul(state[2][j],2)) ^ (GalMul(state[3][j],3));
            temp4 = (GalMul(state[0][j],3)) ^ state[1][j] ^ state[2][j] ^ (GalMul(state[3][j],2));
            state[0][j] = temp1;
            state[1][j] = temp2;
            state[2][j] = temp3;
            state[3][j] = temp4;
    }
}

// Function to print a 1D uint32_t array
void printArray(uint32_t *arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%08x ", arr[i]);
    }
    printf("\n");
}

//Nice helper function to visualize state matrix
void printMatrix(uint8_t (*state)[4]){
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
void tests() {
    /*uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    uint32_t word = RotWord(0x11223344, 8);
    uint32_t word2 = SubWord(0x11223344, sbox);
    printf("RotWord word: 0x%X\n", word);
    printf("SubWord word: 0x%X\n", word2);

    uint32_t ogKey[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t* expandedKey = keyExpansion(ogKey);
    printf("Expanded Key:\n");
    printArray(expandedKey, 4 * R);

    uint8_t state[4][4] = {
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
    uint8_t mixTest[4][4] = {
        {0xdb, 0xf2, 0x01, 0x2d},
        {0x13, 0x0a, 0x01, 0x26},
        {0x53, 0x22, 0x01, 0x31},
        {0x45, 0x5c, 0x01, 0x4c}
    };
    MixColumns(mixTest);
    printf("MixColumns test:\n");
    printMatrix(mixTest);*/
}



void AESencrypt(uint8_t state[4][4], uint32_t* RKeys, uint8_t sbox[256]){
    uint32_t* expandedKey = keyExpansion(RKeys, sbox);
    //This will add the original state to the first 4 bytes of the round keys
    AddKeyHelper(state, expandedKey, 0);
    //These will be the 9 round that are described by the AES Encrpytion Algorithm
    for (int i = 1; i < 10; i++){
        SubBytes(state, sbox);
        shiftRows(state);
        MixColumns(state);
        AddKeyHelper(state, expandedKey, i);
    }
    SubBytes(state,sbox);
    shiftRows(state);
    AddKeyHelper(state, expandedKey, 10);
}

// Function to convert a single hex character to an integer
uint32_t hexCharToInt(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else {
        // Handle invalid input
        fprintf(stderr, "Invalid hex character: %c\n", c);
        exit(EXIT_FAILURE);
    }
}

int main() {
    
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);


    char hexInput[33];  // Room for 32 hex characters plus null terminator
    uint8_t state[4][4];

    printf("Enter a 128-bit plaintext input (32 characters): ");
    if (scanf("%32s", hexInput) != 1) {
        fprintf(stderr, "Error reading input.\n");
        return 1;
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            char hexByte[3];
            hexByte[0] = hexInput[(j * 4 + i) * 2];
            hexByte[1] = hexInput[(j * 4 + i) * 2 + 1];
            hexByte[2] = '\0';

            sscanf(hexByte, "%hhx", &state[i][j]);
        }
    }


    char inputWord[33]; // 32 characters plus null terminator
    uint32_t RKeys[4]; // 128-bit unsigned integer array

    // Input the 32-character word
    printf("Enter a 32-character word (hexadecimal): ");
    scanf("%32s", inputWord);

    // Check if the input word is exactly 32 characters
    if (strlen(inputWord) != 32) {
        fprintf(stderr, "Input word must be exactly 32 characters long.\n");
        return EXIT_FAILURE;
    }

    // Convert the input word to 128-bit unsigned integers
    for (int i = 0; i < 4; i++) {
        RKeys[i] = 0;
        for (int j = 0; j < 8; j++) {
            RKeys[i] <<= 4;
            RKeys[i] |= hexCharToInt(inputWord[i * 8 + j]);
        }
    }


    AESencrypt(state, RKeys, sbox);
    for (int j = 0; j < 4; j++) {
        for (int i = 0; i < 4; i++) {
            printf("%02X", state[i][j]);
        }
    }


    printf("\n");

    return 0; // Exit with success
}
