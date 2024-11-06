#include "../src/aes-128_enc.h"
#include "../src/aes-128_attack.h"
#include "../tools/tools.h"

#define NB_KEYS 10

uint8_t aes128_3_simple_key[AES_128_KEY_SIZE];
uint8_t aes128_3_double_key[2*AES_128_KEY_SIZE];

void oracle_aes128_3_simple(uint8_t *cipher, const uint8_t *plain){
    memcpy(cipher, plain, AES_BLOCK_SIZE);
    aes128_enc(cipher, aes128_3_simple_key, 3, 1);
}

void oracle_aes128_3_double(uint8_t *cipher, const uint8_t *plain){
    memcpy(cipher, plain, AES_BLOCK_SIZE);
    aes128_double_enc(cipher, aes128_3_double_key, 3, 1);
}

void test(){
    uint8_t i;
    for (i = 0; i < NB_KEYS; i++){
        uint8_t key[2*AES_128_KEY_SIZE];
        gen_keys(key, 2*AES_128_KEY_SIZE);
        
        printf("- Testing key n. %d:\n", i);
        printf("Key: {");
        print_key(key, 2*AES_128_KEY_SIZE);
        printf("}\n");

        memcpy(aes128_3_simple_key, key, AES_128_KEY_SIZE);
        memcpy(aes128_3_double_key, key, 2 * AES_128_KEY_SIZE);

        uint8_t lamda_set[AES_BLOCK_SIZE * LAMBDA_SET_SIZE];
        memset(lamda_set, 0, AES_BLOCK_SIZE * LAMBDA_SET_SIZE);
        gen_lambda_set(lamda_set);

        int res_simple = distinguisher(oracle_aes128_3_simple, lamda_set);
        int res_double = distinguisher(oracle_aes128_3_double, lamda_set);

        if (res_simple == 0){
            printf("AES-128 with 3 rounds detected for simple key\n");
        } else {
            printf("AES-128 with 3 rounds not detected for simple key\n");
            exit(1);
        }

        if (res_double == 0){
            printf("AES-128 with 3 rounds detected for double key\n");
        } else {
            printf("AES-128 with 3 rounds not detected for double key\n");
            exit(1);
        }
        printf("Test n. %d PASSED\n", i);
    }
    printf("All tests PASSED\n");
}


int main(){
    printf("Testing distinguisher..\n");
    test();
}