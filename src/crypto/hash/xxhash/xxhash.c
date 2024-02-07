#include <bftvmhors/types.h>
#include "stdlib.h"
#include "xxhash.h"
#include <string.h>


u32 xxhash_32(u8 * hash_output, const u8 * input , u64 length){
  /* create a hash state */
  XXH32_state_t* const state = XXH32_createState();

  /* Initialize state with selected seed */
  XXH32_reset(state, 0);

  if (XXH32_update(state, input, length) == XXH_ERROR) abort();

  /* Produce the final hash value */
  XXH32_hash_t const hash = XXH32_digest(state);

  memcpy(hash_output, &hash, sizeof(XXH32_hash_t));
  XXH32_freeState(state);

  return sizeof(XXH32_hash_t);
}



u32 xxhash_64(u8 * hash_output, const u8 * input , u64 length){

  /* create a hash state */
  XXH64_state_t* const state = XXH64_createState();

  /* Initialize state with selected seed */
  XXH64_reset(state, 0);

  if (XXH64_update(state, input, length) == XXH_ERROR) abort();

  /* Produce the final hash value */
  XXH64_hash_t const hash = XXH64_digest(state);

  memcpy(hash_output, &hash, sizeof(XXH64_hash_t));
  XXH64_freeState(state);

  return sizeof(XXH64_hash_t);
}


u32 xxhash3_64(u8 * hash_output, const u8 * input , u64 length){
  /* create a hash state */
  XXH3_state_t* const state = XXH3_createState();

  /* Initialize state with selected seed */
  (void)XXH3_128bits_reset(state);

  if (XXH3_64bits_update(state, input, length) == XXH_ERROR) abort();

  /* Produce the final hash value */
  XXH64_hash_t const hash = XXH3_64bits_digest(state);

  memcpy(hash_output, &hash, sizeof(XXH64_hash_t));
  XXH3_freeState(state);

  return sizeof(XXH64_hash_t);
}


u32 xxhash3_128(u8 * hash_output, const u8 * input , u64 length){
  /* create a hash state */
  XXH3_state_t* const state = XXH3_createState();

  /* Initialize state with selected seed */
  (void)XXH3_128bits_reset(state);

  if (XXH3_128bits_update(state, input, length) == XXH_ERROR) abort();

  /* Produce the final hash value */
  XXH128_hash_t const hash = XXH3_128bits_digest(state);

  memcpy(hash_output, &hash, sizeof(XXH128_hash_t));
  XXH3_freeState(state);

  return sizeof(XXH128_hash_t);
}
