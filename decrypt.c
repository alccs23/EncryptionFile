#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "aes_utils.h"
#include "aes_encryption.h"



typedef uint8_t Matrix4x4[4][4];
//The subbytes step of AES encryption
//This just modifies the matrix


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
uint8_t GalMul1(uint8_t a, uint8_t b) {
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
            temp[i][c] = GalMul1(state[i][c], 0x0E) ^ GalMul1(state[(i + 1) % 4][c], 0x0B) ^
                         GalMul1(state[(i + 2) % 4][c], 0x0D) ^ GalMul1(state[(i + 3) % 4][c], 0x09);
        }
    }

    // Copy the result back to the original state
    for (int i = 0; i < 4; ++i) {
        for (int c = 0; c < 4; ++c) {
            state[i][c] = temp[i][c];
        }
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






