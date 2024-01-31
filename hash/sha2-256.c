#include <tomcrypt.h>
#include <bftvmhors/types.h>

#define SHA256_OUTPUT_LEN 32


u32 hash_sha2_256(u8 * hash_output, const u8 * input , u64 length){

    hash_state md;
    sha256_init(&md);
    sha256_process(&md, input, length);
    sha256_done(&md, hash_output);
    return SHA256_OUTPUT_LEN;
}

