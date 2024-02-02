#include <bftvmhors/types.h>
#include <tomcrypt.h>


u64 prng_chacha20(u8 ** random_output, u8 * seed, u64 seed_len, u64 prn_output_len){
    s32 err;

    u8 * prn = malloc(prn_output_len);

    if(!prn)
        return 1;

    prng_state prng;

    if ((err = chacha20_prng_start(&prng)) != CRYPT_OK)
        return 1;

    if ((err = chacha20_prng_add_entropy(seed, seed_len, &prng)) != CRYPT_OK)
        return 1;

    if ((err = chacha20_prng_ready(&prng)) != CRYPT_OK)
        return 1;

    chacha20_prng_read(prn, prn_output_len, &prng);

    if ((err = chacha20_prng_done(&prng)) != CRYPT_OK)
        return 1;

    *random_output = prn;

    return 0;
}



