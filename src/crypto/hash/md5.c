#include <bftvmhors/types.h>
#include <openssl/md5.h>

u32 openssl_hash_md5(u8 * hash_output, const u8 * input , u64 length){
  MD5(input, length, hash_output);
  return MD5_DIGEST_LENGTH;
}
