#include "../tools/tools.h"
#include "../src/aes-128_attack.h"

#define NB_KEYS 10

uint8_t oracle_key[AES_128_KEY_SIZE];
void oracle(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE])
{
  memcpy(res, src, AES_BLOCK_SIZE);
  aes128_enc(res, oracle_key, 4, 0);
}

void test(){
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
    printf("All tests PASSED\n");
}

int main(){
    printf("Testing key_recovery..\n");
    test();
}