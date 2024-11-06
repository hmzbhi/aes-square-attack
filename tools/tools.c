#include "tools.h"

void print_key(uint8_t* key,  size_t size)
{
    size_t i;
    for(i = 0; i < size; i++)
    {   
        if (i % 4 == 0 && i != 0)
        {
            printf(" ");
        }
        printf("%02x", key[i]);
    }
}

void gen_keys(uint8_t* data, size_t size)
{
    int urandom = open("/dev/urandom", O_RDONLY);
    if (urandom < 0)
    {
    printf("ERROR: could not open /dev/urandom\n");
    exit(1);
    }

    size_t nb_bytes = read(urandom, data, size);
    if (nb_bytes != size)
    {
    printf("ERROR: could not read %zu bytes from /dev/urandom\n", size);
    exit(1);
    }
}

void xors(uint8_t* res, const uint8_t* a, size_t size)
{
    size_t i;
    for (i=0; i < size; i++)
    {
        res[i] ^= a[i];
    }
}

void gen_lambda_set(uint8_t set[LAMBDA_SET_SIZE * AES_BLOCK_SIZE])
{
    uint8_t rands[AES_BLOCK_SIZE - 1];
    gen_keys(rands, AES_BLOCK_SIZE - 1);

    for (size_t i = 0; i < 256; i++)
    {
        size_t offset = i * AES_BLOCK_SIZE;
        set[offset] = i;
        memcpy(&set[offset + 1], rands, AES_BLOCK_SIZE - 1);
    }
}

void apply_sb_sr(uint8_t block[AES_BLOCK_SIZE])
{   
    uint8_t* S = AES128_PARAMS.s;
    uint8_t tmp;

    for (size_t i = 0; i < AES_BLOCK_SIZE; i += 4) block[i] = S[block[i]];

    tmp = block[1];
    for (size_t i = 1; i <= 13; i += 4) block[i] = S[block[(i + 4) % 16]];
    block[13] = S[tmp];

    tmp = block[2];
    block[2] = S[block[10]];
    block[10] = S[tmp];
    tmp = block[6];
    block[6] = S[block[14]];
    block[14] = S[tmp];

    tmp = block[15];
    block[15] = S[block[3]];
    block[3] = S[block[7]];
    block[7] = S[block[11]];
    block[11] = S[tmp];
}

void reverse_sb_sr(uint8_t block[AES_BLOCK_SIZE])
{   
    uint8_t* Sinv = AES128_PARAMS.sinv;
    uint8_t tmp;

    tmp = block[15];
    block[15] = Sinv[block[3]];
    block[3] = Sinv[block[7]];
    block[7] = Sinv[block[11]];
    block[11] = Sinv[tmp];

    tmp = block[6];
    block[6] = Sinv[block[14]];
    block[14] = Sinv[tmp];
    tmp = block[2];
    block[2] = Sinv[block[10]];
    block[10] = Sinv[tmp];

    tmp = block[1];
    block[1] = Sinv[block[13]];
    block[13] = Sinv[block[9]];
    block[9] = Sinv[block[5]];
    block[5] = Sinv[tmp];

    for (size_t i = 0; i < AES_BLOCK_SIZE; i += 4) block[i] = Sinv[block[i]];
}