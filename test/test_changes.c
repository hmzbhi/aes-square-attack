#include "../tools/tools.h"
#include "../src/aes-128_enc.h"
#include "../src/aes-128_attack.h"

#define NB_KEYS 10

static uint8_t S2[256];
static uint8_t Sinv2[256];

void generate_random_sbox()
{   
    size_t i;
    for (i = 0; i < 256; i++)
    {
        S2[i] = (uint8_t)i;
    }

    size_t j;
    for (j = 0; j < 256; j++)
    {   
        size_t k;
        for (k = 0; k < 256; k++)
        {
            size_t i = rand() % 256;
            uint8_t tmp = S2[k];
            S2[k] = S2[i];
            S2[i] = tmp;
        }
    }

    for (size_t i = 0; i < 256; i++)
    {
        Sinv2[S2[i]] = (uint8_t)i;
    }
    AES128_PARAMS.s = (uint8_t *)S2;
    AES128_PARAMS.sinv = (uint8_t *)Sinv2;
}

void reset_sbox()
{
    AES128_PARAMS.s = (uint8_t *)S;
    AES128_PARAMS.sinv = (uint8_t *)Sinv;
}

void test_cipher(){
    printf("Testing that ciphers are different with different S_boxes..\n");

    uint8_t key[AES_128_KEY_SIZE];
    uint8_t cipher_1[AES_BLOCK_SIZE];
    uint8_t cipher_2[AES_BLOCK_SIZE];

    gen_keys(key, AES_128_KEY_SIZE);
    gen_keys(cipher_1, AES_BLOCK_SIZE);
    memcpy(cipher_2, cipher_1, AES_BLOCK_SIZE);

    printf("Generating random S-box..\n");

    generate_random_sbox();
    aes128_enc(cipher_2, key, 3, 1);

    printf("Resetting S-box..\n");

    reset_sbox();
    aes128_enc(cipher_1, key, 3, 1);

    if (memcmp(cipher_1, cipher_2, AES_BLOCK_SIZE) != 0){
        printf("Ciphers are different\n");
    } else {
        printf("Ciphers are the same\n");
        exit(1);
    }
    printf("Test PASSED\n");

    printf("Testing that ciphers are the different using different polynomes..\n");

    AES128_PARAMS.polynome = 0x1B;
    aes128_enc(cipher_1, key, 3, 1);

    AES128_PARAMS.polynome =  0b01111011;
    aes128_enc(cipher_2, key, 3, 1);

    if (memcmp(cipher_1, cipher_2, AES_BLOCK_SIZE) != 0){
        printf("Ciphers are different\n");
    } else {
        printf("Ciphers are the same\n");
        exit(1);
    }
    printf("Test PASSED\n");
}

uint8_t oracle_key[AES_128_KEY_SIZE];
void oracle(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE])
{
  memcpy(res, src, AES_BLOCK_SIZE);
  aes128_enc(res, oracle_key, 4, 0);
}

void test_retrieve_key(){
    printf("Testing that the key is retrieved correctly withs other params..\n");

    AES128_PARAMS.polynome =  0b01111011;
    generate_random_sbox();

    uint8_t i;
    for (i = 0; i < NB_KEYS; i++){
        uint8_t key[AES_128_KEY_SIZE];
        gen_keys(key, AES_128_KEY_SIZE);
        
        printf("- Testing key n. %d:\n", i);
        printf("Key: {");
        print_key(key, AES_128_KEY_SIZE);
        printf("}\n");

        memcpy(oracle_key, key, AES_128_KEY_SIZE);

        // Try to retrieve the key
        uint8_t recovered_key[AES_128_KEY_SIZE];
        retrieve_key(recovered_key, oracle);

        if (memcmp(key, recovered_key, AES_128_KEY_SIZE) == 0){
            printf("Key recovered successfully\n");
        } else {
            printf("Key not recovered\n");
            exit(1);
        }
        printf("Test n. %d PASSED\n", i);
    }
}

int main(){
    test_cipher();
    test_retrieve_key();
}