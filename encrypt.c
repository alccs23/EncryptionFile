#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define SALT_SIZE 16        // Size of salt for key derivation
#define KEY_SIZE 32         // AES-256 key size
#define IV_SIZE 16          // AES block size
#define ITERATIONS 100000   // Number of PBKDF2 iterations

