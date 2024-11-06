# Rendu TP1

Hamza Bouihi, Bilal Akliai

## Exercice 1: Warming up

### Q.1.1

```c
uint8_t xtime(uint8_t p)
{
 uint8_t m = p >> 7;
 // m=1 if deg(P)=7 (else 0)
 m ^= 1;
 // m= (m XOR 1)
    // Then m=0 if deg(P)=7 (else 1)
 m -= 1;
 // m=0b11111111 if deg(P)=7 (else 0)
 m &= 0x1B;
 // m=0b00011011 if deg(P)=7 (else 0)
 // m is the binary representation of X^8 if deg(P)=7 else it's 0
 // We have X^8 + X^4 + X^3 + X + 1 = 0, thus X^8 = -(X^4 + X^3 + X + 1) = X^4 + X^3 + X + 1
 return ((p << 1) ^ m);
 // (p << 1) is X.P if deg(P)<7 else it's X.P - X^8 (due to overflow)
 // Adding m (XOR is addition in Z/2Z) ensures that we will return X.P
}
```

Knowing that $X^8 + X^6 + X^5 + X^4 + X^3 + X+ 1$ is irreducible over $\mathbb{F}_2[X]$, Then $\mathbb{F}_{2^8} = \mathbb{F}_2[X]/X^8 + X^6 + X^5 + X^4 + X^3 + X+ 1$ and $X^8 = X^6 + X^5 + X^4 + X^3 + X+ 1$. Therefore, we can code `xtime` as follows:

```c
uint8_t xtime_q1(uint8_t p)
{
 uint8_t m = p >> 7;

 m ^= 1;
 m -= 1;
 m &= 0b01111011; // X^6 + X^5 + X^4 + X^3 + X + 1

 return ((p << 1) ^ m);
}
```

### Q.1.2

```c
void prev_aes128_round_key(const uint8_t next_key[16], uint8_t prev_key[16], int round)
{ 
 int i;
 for(i=15; i>=4; i--)
 {
  prev_key[i] = next_key[i] ^ next_key[i-4];
 }

 prev_key[0] = next_key[0] ^ S[next_key[13]] ^ RC[round];
 prev_key[1] = next_key[1] ^ S[next_key[14]];
 prev_key[2] = next_key[2] ^ S[next_key[15]];
 prev_key[3] = next_key[3] ^ S[next_key[12]];
}
```

(The implementation is in [aes-128_enc.c](src/aes-128_enc.c))

### Q.3

To ensure that the function $ F(k_1||k_2, x) = E(k_1, x) \oplus E(k_2, x) $ is non-trivial, it is essential that $ k_1 \neq k_2 $.

Indeed, if $ k_1 = k_2 $, then $ F(k_1||k_2, x) = E(k_1, x) \oplus E(k_2, x) = E(k_1, x) \oplus E(k_1, x) = 0 $, resulting in a constant output of zero, which makes the function trivial.

Now, let’s define $ AES_3' $, a variant of $ AES_3 $ in the style of $ F $, where we take $ k_1 \neq k_2 $. In this case:

$$
AES_3'(k_1||k_2, x) = AES_3(k_1, x) \oplus AES_3(k_2, x)
$$

We observe that:

$$
\begin{align}
&AES_3'(k_1||k_2, p_0) \oplus \dots \oplus AES_3'(k_1||k_2, p_{255}) \\
&= AES_3(k_1, p_0) \oplus AES_3(k_2, p_0) \oplus \dots \oplus AES_3(k_1, p_{255}) \oplus AES_3(k_2, p_{255}) \\
&= \Big(AES_3(k_1, p_0) \oplus \dots \oplus AES_3(k_1, p_{255})\Big) \oplus \Big(AES_3(k_2, p_0) \oplus \dots \oplus AES_3(k_2, p_{255})\Big) \\
&= 0 \oplus 0 \\
&= 0
\end{align}
$$

The implementation of the distinguisher is in [aes-128_attack.c](src/aes-128_attack.c)

The distinguisher relies on an oracle provided as a function pointer. In our tests, we define one oracle function for standard encryption and another for $F$-style encryption. This allows us to verify that the same distinguisher can operate with both types of oracles.
(implementation in [test_distinguisher.c](test/test_distinguisher.c))

## Exercice 2: Key-recovery attack

### Q.2.1

The implementation of the attack is in [aes-128_attack.c](src/aes-128_attack.c)

The implementation of the tests is in [test_attack.c](test/test_attack.c)

The `retrieve_key` function generates random lambda sets and, for each set, attempts to recover each byte of the key. It does this by guessing each byte and verifying if the guess could be correct, using a method similar to the distinguisher. Once all 16 guessed bytes seem correct, it confirms the key's accuracy by comparing the ciphertexts produced with the recovered key to those provided by the oracle. As a result, the function typically requires multiple lambda sets to successfully determine the correct key.

Even though they are not included in the code, we have thoroughly tested our intermediate functions, such as `apply_sb_sr` and `reverse_sb_sr`.

### Q.2.2

For this question, we modified `aes_128_enc.h` and `aes_128_enc.c` to allow configuration of the S-box used by the AES implementation, as well as the irreducible polynomial that defines $\mathbb{F}_{2^{8}}$.

We created the following structure to store these parameters (see [aes-128_enc.h](src/aes-128_enc.h)):

```c
struct aes128
{
 uint8_t *s;
 uint8_t *sinv;
 uint8_t polynome;
};

struct aes128 AES128_PARAMS = {
  .s = (uint8_t *)S,
  .sinv = (uint8_t *)Sinv,
  .polynome = 0x1B,
};
```

With this setup, We can use random S-boxes by calling `generate_random_sbox()` in [test_changes.c](test/test_changes.c). This function pseudo-randomly shuffles the identity permutation to create a pseudo-random S-box, then calculates the inverse S-box and updates the AES128_PARAMS structure to use these new S-boxes.
