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


// AES-128 round constants
//The index at 0 is a placeholder, because SubWord works an 1 index. The placeholder will never be called
const uint32_t Rcon[AES_ROUNDS+1] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
};

//Length of the key in 32-bit words: 4 words for AES-128
int N = 4;

//Number of round keys needed
int R = 11;

typedef uint8_t Matrix4x4[4][4];
//The subbytes step of AES encryption
//This just modifies the matrix
void SubBytes(uint8_t matrix[4][4], uint8_t sbox[256]){
    for (int j = 0; j < 4; j++){
        for (int i = 0; i < 4; i++) {
            matrix[i][j] = sbox[matrix[i][j]];
        }
    }
}

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

/*Simple inverse mapping of the sbox that i already made*/
void initialize_aes_inverse_sbox(uint8_t inverse_sbox[256]){
	uint8_t sbox[256];
    initialize_aes_sbox(sbox);
      // Compute the inverse S-box by reversing the mapping
    for (int i = 0; i < 256; i++) {
        inverse_sbox[sbox[i]] = (unsigned char)i;
    }
}

void invShiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Inverse shift the second row one position to the right (circular shift)
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Inverse shift the third row two positions to the right (circular shift)
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Inverse shift the fourth row three positions to the right (circular shift)
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}


/*Adapted version from https://en.wikipedia.org/wiki/Rijndael_MixColumns, since my previous code was wrong for this case, but correct for the other IDK MAN.*/
// Galois Multiplication of two bytes
uint8_t GalMul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        uint8_t carry = a & 0x80;
        a <<= 1;
        if (carry) {
            a ^= 0x1B;  // 0x1B is the irreducible polynomial for AES
        }
        b >>= 1;
    }
    return p;
}

// Inverse MixColumns operation for AES-128, redefined and made nicer to work with new definition*/
void InvMixColumns(uint8_t state[4][4]) {
    uint8_t temp[4][4];

    for (int c = 0; c < 4; ++c) {
        for (int i = 0; i < 4; ++i) {
            temp[i][c] = GalMul(state[i][c], 0x0E) ^ GalMul(state[(i + 1) % 4][c], 0x0B) ^
                         GalMul(state[(i + 2) % 4][c], 0x0D) ^ GalMul(state[(i + 3) % 4][c], 0x09);
        }
    }

    // Copy the result back to the original state
    for (int i = 0; i < 4; ++i) {
        for (int c = 0; c < 4; ++c) {
            state[i][c] = temp[i][c];
        }
    }
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

void AESDecrypt(uint8_t state[4][4], uint32_t* RKeys, uint8_t inverseSbox[256], uint8_t sbox[256]){
    uint32_t* expandedKey = keyExpansion(RKeys, sbox);
    AddKeyHelper(state, expandedKey, 10);
    for(int i = 9; i > 0; i--){   
        invShiftRows(state);
        SubBytes(state, inverseSbox);
        AddKeyHelper(state, expandedKey, i);
        InvMixColumns(state);
    }
    invShiftRows(state);
    SubBytes(state, inverseSbox);
    AddKeyHelper(state, expandedKey, 0);
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
    uint8_t inverseSbox[256];
    initialize_aes_inverse_sbox(inverseSbox);
    initialize_aes_sbox(sbox);

    char hexInput[33];  // Room for 32 hex characters plus null terminator
    uint8_t state[4][4];

    printf("Enter a 128-bit Encrypted input (32 characters): ");
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


    AESDecrypt(state, RKeys, inverseSbox, sbox);
    printMatrix(state);

    printf("\n");

    return 0; // Exit with success
}





