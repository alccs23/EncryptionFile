#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include "aes_utils.h"
#include "aes_encryption.h"


void uint32_to_state(uint32_t value, uint8_t state[4][4]) {
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            // Extract a byte from the 32-bit value using bit manipulation
            uint8_t byte = (value >> (8 * (3 - col))) & 0xFF;
            
            // Fill the state matrix
            state[row][col] = byte;
        }
    }
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




int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <encrypt/decrypt> <key> <input_file> <output_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *operation = argv[1];
    char *inputWord = argv[2];
    char *inputFileName = argv[3];
    char *outputFileName = argv[4];

    FILE *file;
    FILE *outputFile;
    uint8_t sbox[256];
    initialize_aes_sbox(sbox);
    char hexInput[34]; // Buffer to hold each line (including the null terminator)
    size_t chunkSize = 32; // The size of each line
    uint8_t state[4][4];
    uint32_t RKeys[4]; // 128-bit unsigned integer array
    uint8_t inverseSbox[256];
    initialize_aes_inverse_sbox(inverseSbox);

    // Convert the input word to 128-bit unsigned integers
    for (int i = 0; i < 4; i++) {
        RKeys[i] = 0;
        for (int j = 0; j < 8; j++) {
            RKeys[i] <<= 4;
            RKeys[i] |= hexCharToInt(inputWord[i * 8 + j]);
        }
    }

    // Open the input file for reading
    file = fopen(inputFileName, "rb"); // Use "rb" for binary mode

    if (file == NULL) {
        perror("Error opening input file");
        return 1;
    }

    // Create and open the output file for writing
    outputFile = fopen(outputFileName, "w"); // Use "w" for write mode

    if (outputFile == NULL) {
        perror("Error creating output file");
        return 1;
    }

    // Read and process each line separately
    while (fgets(hexInput, sizeof(hexInput), file) != NULL) {
        // Trim any leading or trailing whitespace or line endings
        char *trimmedInput = strtok(hexInput, "\r\n\t ");
        if (trimmedInput == NULL) {
            continue; // Skip empty lines or lines with only whitespace
        }

        // Check if the line has the expected length
        if (strlen(trimmedInput) != chunkSize) {
            printf("Invalid line size: %zu\n", strlen(trimmedInput));
            break; // Stop if the line size is invalid
        }

        // Convert the input words to 128-bit unsigned integers
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                char hexByte[3];
                hexByte[0] = trimmedInput[(j * 4 + i) * 2];
                hexByte[1] = trimmedInput[(j * 4 + i) * 2 + 1];
                hexByte[2] = '\0';

                sscanf(hexByte, "%hhx", &state[i][j]);
            }
        }
         if (strcmp(operation, "encrypt") == 0) {
        AESencrypt(state, RKeys, sbox);
        } else if (strcmp(operation, "decrypt") == 0) {
        AESDecrypt(state, RKeys, inverseSbox, sbox);
        } else {
        fprintf(stderr, "Invalid operation: %s\n", operation);
        return EXIT_FAILURE;
        }
        // Write the encrypted data to the output file
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                fprintf(outputFile, "%02x", state[i][j]);
            }
        }
        fprintf(outputFile, "\n");
    }

    // Close the files
    fclose(file);
    fclose(outputFile);

    return 0;
}
