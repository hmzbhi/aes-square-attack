#include "../tools/tools.h"
#include "../src/aes-128_enc.h"

#define NB_KEYS 10

void test(){
    
    // Keys of §A.1 and §C.1
    uint8_t keys[NB_KEYS][AES_128_KEY_SIZE] = {
      {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}, 
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};
    
    // generates other random keys
    gen_keys((uint8_t *)&(keys[2]), AES_128_KEY_SIZE*(NB_KEYS-2));

    int i;
    for(i = 0; i < NB_KEYS; i++){
        uint8_t prev_key[AES_128_KEY_SIZE];
        uint8_t next_key[AES_128_KEY_SIZE];
        

        memcpy(prev_key, keys[i], AES_128_KEY_SIZE);
        printf("- Testing key n. %d:\n", i);
        printf("Key: {");
        print_key(prev_key, AES_128_KEY_SIZE);
        printf("}\n");

        uint8_t j;
        for(j = 0; j <= 3; j++){
            next_aes128_round_key(prev_key, next_key, j);
            uint8_t res_prev_key[AES_128_KEY_SIZE];
            prev_aes128_round_key(next_key,res_prev_key, j);
            
            uint8_t k;
            for (k = 0; k < AES_128_KEY_SIZE; k++){
                if (res_prev_key[k] != prev_key[k]){
                    printf("Error in round %d, byte %d\n", j, k);
                    printf("Expected: %02x\n", prev_key[k]);
                    printf("Got: %02x\n", res_prev_key[k]);

                    exit(1);
                }
            }
        }
        printf("Test n. %d PASSED\n", i);
    }
    printf("All tests PASSED\n");
}

int main(){
    printf("Testing prev_aes128_round_key..\n");
    test();
}