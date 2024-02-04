#include <bftvmhors/types.h>
#include <tomcrypt.h>
#include <openssl/sha.h>

#define SHA256_OUTPUT_LEN 32

u32 ltc_hash_sha2_256(u8 * hash_output, const u8 * input , u64 length){
    hash_state md;
    sha256_init(&md);
    sha256_process(&md, input, length);
    sha256_done(&md, hash_output);
    return SHA256_OUTPUT_LEN;
}


u32 openssl_hash_sha2_256(u8 * hash_output, const u8 * input , u64 length){
  SHA256(input, length, hash_output);
  return SHA256_OUTPUT_LEN;
}
