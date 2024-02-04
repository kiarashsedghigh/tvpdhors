#include <bftvmhors/types.h>
#include <openssl/sha.h>

u32 openssl_hash_sha1(u8 * hash_output, const u8 * input , u64 length){
  SHA1(input, length, hash_output);
  return SHA_DIGEST_LENGTH;
}
