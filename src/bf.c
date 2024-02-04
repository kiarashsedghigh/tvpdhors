#include <bftvmhors/bf.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/format.h>
#include <bftvmhors/hash.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TODO Check for size to be *8
sbf_hp_t sbf_new_hp(u32 size, u32 num_hash_functions, const u8 *hash_family) {
  sbf_hp_t sbf_hp;
  sbf_hp.size = size;
  sbf_hp.num_hash_functions = num_hash_functions;
  sbf_hp.hash_family = hash_family;
  return sbf_hp;
}

// TODO replace hash function, error return
u32 sbf_create(sbf_t *sbf, const sbf_hp_t *sbf_hp) {
  sbf->size = sbf_hp->size;
  sbf->num_hash_functions = sbf_hp->num_hash_functions;
  sbf->bv = malloc(sbf->size / 8);

  /* Zero out the bit vector */
  for (u32 i = 0; i < sbf->size / 8; i++) sbf->bv[i] = 0;

  sbf->hash_functions = malloc(sizeof(u32(*)(u8 *, const u8 *, u64)) * sbf->size);

  u32 (*selected_hash_function)(u8 *, const u8 *, u64);

  if (strcmp(sbf_hp->hash_family, "ltc_sha256") == 0)
    selected_hash_function = ltc_hash_sha2_256;
  else if (strcmp(sbf_hp->hash_family, "openssl_sha256") == 0)
    selected_hash_function = openssl_hash_sha2_256;
  else if (strcmp(sbf_hp->hash_family, "jenkins_oaat") == 0)
    selected_hash_function = jenkins_oaat;
  else if (strcmp(sbf_hp->hash_family, "fnv64_0") == 0)
    selected_hash_function = fnv64_0;
  else if (strcmp(sbf_hp->hash_family, "fnv64_1") == 0)
    selected_hash_function = fnv64_1;
  else if (strcmp(sbf_hp->hash_family, "fnv64_1a") == 0)
    selected_hash_function = fnv64_1a;
  else  // Default
    selected_hash_function = ltc_hash_sha2_256;

  for (u32 i = 0; i < sbf->num_hash_functions; i++) sbf->hash_functions[i] = selected_hash_function;

  return 0;
}

void sbf_destroy(const sbf_t *sbf) {
  free(sbf->hash_functions);
  free(sbf->bv);
}

void sbf_insert(const sbf_t *sbf, const u8 *input, u64 length) {
  u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];

  /* We concat the given input with the 4-byte index of the SBF hash function */
  u8 *concat_buffer = malloc(length + sizeof(u32));

  for (u32 i = 0; i < sbf->num_hash_functions; i++) {
    u32 concat_buffer_length = concat_buffers(concat_buffer, input, length, &i, 4);

    u32 hash_size = sbf->hash_functions[i](hash_buffer, concat_buffer, concat_buffer_length);

    /* Convert the hash value to BigNum for further evaluations.
     *
     * We aim to compute the following to get an index for the SBF:
     *              target_idx = hash % SBF_SIZE
     * */
    BIGNUM *hash_bn = BN_new();
    BIGNUM *sbf_size_bn = BN_new();
    BIGNUM *target_idx_bn = BN_new();

    /* Convert the computed hash to a BIGNUM */
    BN_bin2bn(hash_buffer, hash_size, hash_bn);
    BN_set_word(sbf_size_bn, sbf->size);

    /* Compute hash % SBF_SIZE */
    BN_mod(target_idx_bn, hash_bn, sbf_size_bn, BN_CTX_new());

    /* Converting the result to integer in base 10 */
    u32 target_idx = strtol(BN_bn2dec(target_idx_bn), NULL, 10);

    /* Read the target byte and set the appropriate bit and write back */
    u8 sbf_target_byte = sbf->bv[BITS_2_BYTES(target_idx)];
    sbf_target_byte |= 1 << (8 - BITS_MOD_BYTES(target_idx) - 1);
    sbf->bv[BITS_2_BYTES(target_idx)] = sbf_target_byte;
  }
  free(concat_buffer);
}

u32 sbf_check(const sbf_t *sbf, const u8 *input, u64 input_length) {
  u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];
  u8 *concat_buffer = malloc(input_length + sizeof(u32));

  for (u32 i = 0; i < sbf->num_hash_functions; i++) {
    u8 concat_buffer_length = concat_buffers(concat_buffer, input, input_length, (u8 *)&i, 4);

    u32 hash_size = sbf->hash_functions[i](hash_buffer, concat_buffer, concat_buffer_length);


    /* Convert the hash value to BigNum for further evaluations.
     *
     * We aim to compute the following to get an index for the SBF:
     *              target_idx = hash % SBF_SIZE
     * */
    BIGNUM *hash_bn = BN_new();
    BIGNUM *sbf_size_bn = BN_new();
    BIGNUM *target_idx_bn = BN_new();

    /* Convert the computed hash to a BIGNUM */
    BN_bin2bn(hash_buffer, hash_size, hash_bn);
    BN_set_word(sbf_size_bn, sbf->size);

    /* Compute hash % SBF_SIZE */
    BN_mod(target_idx_bn, hash_bn, sbf_size_bn, BN_CTX_new());

    /* Converting the result to integer in base 10 */
    u32 target_idx = strtol(BN_bn2dec(target_idx_bn), NULL, 10);

    /* Read the target bit and check for the set/unset state of the desired bit */
    u8 sbf_target_byte = sbf->bv[BITS_2_BYTES(target_idx)];
    if (!(sbf_target_byte & (1 << (8 - BITS_MOD_BYTES(target_idx) - 1)))) {
      free(concat_buffer);
      return SBF_ELEMENT_ABSENTS;
    }
  }
  free(concat_buffer);
  return SBF_ELEMENT_EXISTS;
}