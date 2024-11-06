#include "../src/aes-128_enc.h"
#include "../tools/tools.h"

#define LAMBDA_SET_SIZE 256

extern const uint8_t SB_SR_REV[AES_128_KEY_SIZE];

/**
 * @brief Distinguishes AES-128 from a random permutation using a Λ-set.
 * 
 * This function checks if the XOR of encrypted Λ-set elements is zero, a property of 3-round AES.
 * 
 * @param oracle A function pointer to the encryption routine, taking a 16-byte plaintext (src) and producing
 *               a 16-byte ciphertext (res).
 * @param lambda_set Pointer to the Λ-set of plaintexts (size LAMBDA_SET_SIZE * AES_BLOCK_SIZE).
 * 
 * @return int Returns 0 if the oracle behaves like AES-128, and 1 if it behaves like a random permutation.
 */
int distinguisher(void (*oracle)(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE]), uint8_t *lambda_set);

/**
 * @brief Verifies if a recovered key is correct by checking it against the oracle.
 * 
 * This function generates random plaintexts, encrypts them with the oracle, and then with the recovered key.
 * If the results match, the key is considered correct.
 * 
 * @param key The recovered key to verify.
 * @param oracle A function pointer to the encryption routine, taking a 16-byte plaintext (src) and producing
 *               a 16-byte ciphertext (res).
 * @param checks The number of plaintexts to encrypt and compare.
 * 
 * @return int Returns 1 if the key is correct, and 0 otherwise.
 */
int verify_recovered_key(uint8_t key[AES_128_KEY_SIZE], void (*oracle)(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE]), size_t checks);

/**
 * @brief Recovers the AES-128 key used by the oracle.
 * 
 * This function recovers the AES-128 key used by the oracle by distinguishing it from a random permutation.
 * 
 * @param recovered_key The buffer where the recovered key will be stored.
 * @param oracle A function pointer to the encryption routine, taking a 16-byte plaintext (src) and producing
 *               a 16-byte ciphertext (res).
 */
void retrieve_key(uint8_t recovered_key[AES_BLOCK_SIZE], void (*oracle)(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE]));