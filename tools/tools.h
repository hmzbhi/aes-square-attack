#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../src/aes-128_enc.h"

/**
 * @brief Prints the AES key in hexadecimal format, grouping bytes for readability.
 * 
 * @param key Pointer to the key data.
 * @param size Size of the key in bytes.
 */
void print_key(uint8_t* key,  size_t size);

/**
 * @brief Generates random key data by reading from /dev/urandom.
 * 
 * @param data Pointer to the buffer where the random key will be stored.
 * @param size Number of random bytes to generate.
 */
void gen_keys(uint8_t* data, size_t size);

/**
 * @brief XORs two byte arrays of the same size.
 * 
 * @param res Pointer to the buffer where the result will be stored.
 * @param a Pointer to the first byte array.
 * @param size Size of the byte arrays in bytes.
 */
void xors(uint8_t* res, const uint8_t* a, size_t size);

/**
 * @brief Generates a Λ-set of plaintexts for the distinguisher.
 * 
 * @param set Pointer to the buffer where the Λ-set will be stored.
 */
void gen_lambda_set(uint8_t set[LAMBDA_SET_SIZE * AES_BLOCK_SIZE]);

/**
 * @brief Applies AES SubBytes and ShiftRows transformations to a 16-byte block.
 * 
 * @param block The 16-byte block to be transformed in-place.
 */
void apply_sb_sr(uint8_t block[AES_BLOCK_SIZE]);

/**
 * @brief Applies the inverse AES SubBytes and ShiftRows transformations to a 16-byte block.
 * 
 * @param block The 16-byte block to be transformed in-place.
 */
void reverse_sb_sr(uint8_t block[AES_BLOCK_SIZE]);
