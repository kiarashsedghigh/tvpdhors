#include <bftvmhors/types.h>
#include "./wyhashlib/wyhash.h"



u32 wyhash_64(u8 * hash_output, const char * input , u64 length) {
  u64 hash = wyhash(input, length, 0 , _wyp);
  memcpy(hash_output, &hash, sizeof(u64));
  return 0;
}

