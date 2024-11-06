#include "aes-128_attack.h"

#define MAX_RECOVERY_STEPS 12

const uint8_t SB_SR_REV[AES_128_KEY_SIZE] = {
    0, 5, 10, 15,
    4, 9, 14, 3,
    8, 13, 2, 7,
    12, 1, 6, 11};

int distinguisher(void (*oracle)(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE]), uint8_t *lambda_set)
{
    uint8_t sum[AES_BLOCK_SIZE];
    memset(sum, 0, AES_BLOCK_SIZE);

    uint8_t ciphered[AES_BLOCK_SIZE];

    size_t i;
    for (i=0; i < LAMBDA_SET_SIZE; i++){
        oracle(ciphered, lambda_set + i * AES_BLOCK_SIZE);
        xors(sum, ciphered, AES_BLOCK_SIZE);
    }

    for (i=0; i < AES_BLOCK_SIZE; i++){
        if (sum[i] != 0){
            return 1;
        }
    }
    return 0;
}

int verify_recovered_key(uint8_t key[AES_128_KEY_SIZE], void (*oracle)(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE]), size_t checks)
{
    uint8_t oracle_output[AES_BLOCK_SIZE];
    uint8_t aes_output[AES_BLOCK_SIZE];

    size_t i;
    for (i = 0; i < checks; i++)
    {
        gen_keys(aes_output, AES_BLOCK_SIZE);
        oracle(oracle_output, aes_output);
        aes128_enc(aes_output, key, 4, 0);
        
        if (memcmp(oracle_output, aes_output, AES_BLOCK_SIZE) != 0)
            return 0;
    }
    return 1;
}

void retrieve_key(uint8_t recovered_key[AES_BLOCK_SIZE], void (*oracle)(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE]))
{
    uint8_t guessed_key[AES_BLOCK_SIZE] = {0};
    uint8_t lambda_set[LAMBDA_SET_SIZE * AES_BLOCK_SIZE];
    uint8_t step = 0;

    while (step < MAX_RECOVERY_STEPS)
    {
        gen_lambda_set(lambda_set);
        uint8_t ciphered_set[LAMBDA_SET_SIZE * AES_BLOCK_SIZE];
        
        for (size_t i = 0; i < LAMBDA_SET_SIZE; i++)
            oracle(ciphered_set + (i * AES_BLOCK_SIZE), lambda_set + (i * AES_BLOCK_SIZE));

        uint8_t plausible_guesses = 0;

        for (uint8_t s = 0; s < AES_128_KEY_SIZE; s++)
        {
            for (size_t i = 0; i < 256; i++)
            {
                uint8_t sum[AES_BLOCK_SIZE] = {0};
                uint8_t block[AES_BLOCK_SIZE];

                for (size_t j = 0; j < LAMBDA_SET_SIZE; j++)
                {
                    memcpy(block, ciphered_set + (j * AES_BLOCK_SIZE), AES_BLOCK_SIZE);
                    xors(block, guessed_key, AES_BLOCK_SIZE);
                    reverse_sb_sr(block);
                    xors(sum, block, AES_BLOCK_SIZE);
                }

                if (sum[SB_SR_REV[s]] == 0)
                {
                    plausible_guesses++;
                    break;
                }
                guessed_key[s]++;
            }
        }

        if (plausible_guesses == AES_128_KEY_SIZE)
        {
            uint8_t temp_key[AES_128_KEY_SIZE];
            memcpy(temp_key, guessed_key, AES_128_KEY_SIZE);
            for (int round = 3; round >= 0; round--)
            {
                prev_aes128_round_key(temp_key, recovered_key, round);
                memcpy(temp_key, recovered_key, AES_128_KEY_SIZE);
            }

            if (verify_recovered_key(recovered_key, oracle, 6))
            {
                printf("Key recovered in %d steps\n", step + 1);
                return;
            }
        }
        step++;
    }
    printf("Key recovery unsuccessful after %d steps\n", MAX_RECOVERY_STEPS);
}