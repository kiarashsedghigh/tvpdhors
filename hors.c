#include <bftvmhors/hash.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/file.h>
#include <bftvmhors/format.h>
#include <bftvmhors/hors.h>
#include <bftvmhors/prng.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_FILE_MAX_LENGTH 300

/// HORS key generation
/// \param keys Pointer to the HORS keys
/// \param hp Pointer to the HORS HP
/// \return HORS_KEYGEN_SUCCESS, HORS_KEYGEN_FAILED
u32 hors_keygen(hors_keys_t* keys, hors_hp_t* hp) {
  /* Read the seed file */
  u8* seed;

  u32 seed_len = read_file(&seed, hp->seed_file);

  /* Generate the t private keys */
  prng_chacha20(&keys->sk, seed, seed_len, BITS_2_BYTES(hp->l) * hp->t);

  /* Generate the PK */
  keys->pk = malloc(BITS_2_BYTES(hp->l) * hp->t);

  /* Compute OWF of privates as public key */
  for (u32 i = 0; i < hp->t; i++) {
    u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];
    u32 hash_size = ltc_hash_sha2_256(message_hash, keys->sk + i * BITS_2_BYTES(hp->l), BITS_2_BYTES(hp->l));
    memcpy(keys->pk + i * BITS_2_BYTES(hp->l), message_hash, hash_size);
  }

  return HORS_KEYGEN_SUCCESS;
}

/// Performing the rejection sampling on the input message to achieve higher security in HORS-based signatures. (Assumes rejection sampling is always successful)
/// \param k HORS k parameter
/// \param t HORS t parameter
/// \param ctr Pointer to the rejection sampling 4-byte variable where the found counter will be written into it
/// \param message_hash Pointer to a buffer for writing the resulting hash into for not doing it again when signing
/// \param message  Pointer to the message to check signature on
/// \param message_len  Length of the input message
/// \return HORS_REJECTION_SAMPLING_SUCCESS, HORS_REJECTION_SAMPLING_FAILED
static u32 rejection_sampling(u32 k, u32 t, u32* ctr, u8* message_hash, u8* message, u64 message_len) {
  /* A message_counter_buffer containing the input message and the incremental counter */
  u8* message_counter_buffer = malloc(message_len + sizeof(u32));

  /* Creating a dictionary to see if a portion has already been generated from the hash of the message */
  u8* portion_number_dict = malloc(t);

  /* HORS log(t), defining size of the bit slices */
  u32 bit_slice_len = log2(t);

  while (1) {
    memcpy(message_counter_buffer, message, message_len);
    memcpy(message_counter_buffer + message_len, ctr, sizeof(u32));
    u32 ctr_found = 1;

    /* Clear the dictionary */
    for (u32 i = 0; i < t; i++) portion_number_dict[i] = 0;

    ltc_hash_sha2_256(message_hash, message_counter_buffer, message_len + sizeof(u32));

    for (u32 i = 0; i < k; i++) {
      u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);
      if (portion_number_dict[portion_value]) {
        ctr_found = 0;
        break;
      } else
        portion_number_dict[portion_value] = 1;
    }
    if (ctr_found) {
      free(message_counter_buffer);
      free(portion_number_dict);
      return HORS_REJECTION_SAMPLING_SUCCESS;
    }
    *ctr++;
    /* If rejection sampling goes infinite times, we will reach 0 again in a 4-byte variable */
    if (!*ctr) return HORS_REJECTION_SAMPLING_FAILED;
  }
}

/// Checks if the rejection sampling has been done by checking if the passed counter is a valid counter
/// \param k HORS k parameter
/// \param t HORS t parameter
/// \param ctr 4-byte rejection sampling counter
/// \param message_hash Pointer to a buffer for writing the resulting hash into for not doing it again when signing
/// \param message  Pointer to the message to check signature on
/// \param message_len  Length of the input message
/// \return HORS_REJECTION_SAMPLING_DONE, HORS_REJECTION_SAMPLING_NOT_DONE
static u32 rejection_sampling_status(u32 k, u32 t, u32 ctr, u8* message_hash, u8* message, u64 message_len) {
  /* A message_counter_buffer containing the input message and the incremental counter */
  u8* message_counter_buffer = malloc(message_len + sizeof(u32));

  /* Creating a dictionary to see if a portion has already been generated from the hash of the message */
  u8* portion_number_dict = malloc(t);

  /* HORS log(t), defining size of the bit slices */
  u32 bit_slice_len = log2(t);

  memcpy(message_counter_buffer, message, message_len);
  memcpy(message_counter_buffer + message_len, &ctr, sizeof(u32));
  u32 ctr_found = 1;

  /* Clear the dictionary */
  for (u32 i = 0; i < t; i++) portion_number_dict[i] = 0;

  ltc_hash_sha2_256(message_hash, message_counter_buffer, message_len + sizeof(u32));
  for (u32 i = 0; i < k; i++) {
    u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);
    if (portion_number_dict[portion_value])
      return HORS_REJECTION_SAMPLING_NOT_DONE;
    else
      portion_number_dict[portion_value] = 1;
  }
  return HORS_REJECTION_SAMPLING_DONE;
}

/// Passing the HORS hyper parameters and the keys it creates a HORS signer
/// \param hp HORS hyper parameter
/// \param keys HORS keys
/// \return HORS signer
hors_signer_t hors_new_signer(hors_hp_t* hp, hors_keys_t* keys) {
  /* State has not been set as this is a one-time HORS */
  hors_signer_t signer;
  signer.keys = keys;
  signer.hp = hp;
  return signer;
}

/// HORS signer
/// \param signature Pointer to the output signature struct
/// \param signer Pointer to the signer signer struct
/// \param message  Pointer to the message to check signature on
/// \param message_len  Length of the input message
/// \return HORS_SIGNING_SUCCESS, HORS_SIGNING_FAILED
u32 hors_sign(hors_signature_t* signature, hors_signer_t* signer, u8* message, u64 message_len) {
  u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

  /* Perform rejection sampling */
  if (signer->hp->do_rejection_sampling) {
    if (rejection_sampling(signer->hp->k, signer->hp->t, &signature->rejection_sampling_counter, message_hash, message, message_len) == HORS_REJECTION_SAMPLING_FAILED) return HORS_SIGNING_FAILED;

  } else
    /* Hashing the message */
    ltc_hash_sha2_256(message_hash, message, message_len);

  /* HORS log(t), defining size of the bit slices */
  u32 bit_slice_len = log2(signer->hp->t);

  /* Extract the portions from the private key and write to the signature */
  for (u32 i = 0; i < signer->hp->k; i++) {
    u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);
    memcpy(&signature->signature[i * BITS_2_BYTES(signer->hp->l)], &signer->keys->sk[portion_value * BITS_2_BYTES(signer->hp->l)], BITS_2_BYTES(signer->hp->l));
  }
  return HORS_SIGNING_SUCCESS;
}

/// Passing the HORS public key, returns a HORS verifier
/// \param pk HORS public key
/// \return HORS verifier
hors_verifier_t hors_new_verifier(u8* pk) {
  /* State has not been set as this is a one-time HORS */
  hors_verifier_t verifier;
  verifier.pk = pk;
  return verifier;
}

/// HORS verifier
/// \param verifier Pointer to the HORS verifier struct
/// \param hp Pointer to the HORS hyper parameter struct
/// \param signature Pointer to the HORS signature struct
/// \param message  Pointer to the message to check signature on
/// \param message_len Length of the input message
/// \return HORS_SIGNATURE_VERIFIED and HORS_SIGNATURE_REJECTED
u32 hors_verify(hors_verifier_t* verifier, hors_hp_t* hp, hors_signature_t* signature, u8* message, u64 message_len) {
  u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

  if (hp->do_rejection_sampling) {
    if (rejection_sampling_status(hp->k, hp->t, signature->rejection_sampling_counter, message_hash, message, message_len) == HORS_REJECTION_SAMPLING_NOT_DONE) return HORS_SIGNATURE_REJECTED;
  } else
    /* Hashing the message */
    ltc_hash_sha2_256(message_hash, message, message_len);

  /* HORS log(t), defining size of the bit slices */
  u32 bit_slice_len = log2(hp->t);

  for (u32 i = 0; i < hp->k; i++) {
    u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);

    /* Current signature element (sk) */
    u8* pointed_signature_portion = &signature->signature[i * BITS_2_BYTES(hp->l)];

    /* Hash the current signature element (sk) for further comparison */
    u8 sk_hash[HASH_MAX_LENGTH_THRESHOLD];
    ltc_hash_sha2_256(sk_hash, pointed_signature_portion, BITS_2_BYTES(hp->l));

    /* Compare the hashed current signature element (sk) with public key indexed by portion_value */
    if (memcmp(sk_hash, &verifier->pk[portion_value * BITS_2_BYTES(hp->l)], BITS_2_BYTES(hp->l)) != 0) return HORS_SIGNATURE_REJECTED;
  }
  return HORS_SIGNATURE_ACCEPTED;
}

/// Passing the config file, it creates a new hyper parameter struct
/// \param new_hp Pointer to the hyper parameter struct
/// \param config_file Path of the config file
/// \return HORS_NEW_HP_SUCCESS and HORS_NEW_HP_FAILED
u32 hors_new_hp(hors_hp_t* new_hp, const u8* config_file) {
  u8 line_buffer[CONFIG_FILE_MAX_LENGTH];

  read_file_line(line_buffer, CONFIG_FILE_MAX_LENGTH, NULL);

  while (!read_file_line(line_buffer, CONFIG_FILE_MAX_LENGTH, config_file)) {
    u8* trimmed_line = str_trim(line_buffer);

    /* Ignore empty lines */
    if (!strlen(trimmed_line)) continue;

    char* token;
    char* delim = "=";

    /* Get the first token */
    token = strtok(trimmed_line, delim);
    token = str_trim(token);

    /* walk through other tokens */
    while (token != NULL) {
      /* If the line is a comment, ignore it */
      if (token[0] == '#') break;

      if (!strcmp(token, "t")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->t = strtol(token, NULL, 10);
        } else
          return HORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "k")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->k = strtol(token, NULL, 10);
        } else
          return HORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "l")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->l = strtol(token, NULL, 10);
        } else
          return HORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "rejection_sampling")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          if (strcmp(token, "true") == 0)
            new_hp->do_rejection_sampling = 1;
          else
            new_hp->do_rejection_sampling = 0;
        } else
          return HORS_NEW_HP_FAILED;
      } else if (!strcmp(token, "seed")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->seed_file = malloc(strlen(token));
          memcpy(new_hp->seed_file, token, strlen(token));
        } else
          return HORS_NEW_HP_FAILED;
      }
      token = strtok(NULL, delim);
    }
  }
  return HORS_NEW_HP_SUCCESS;
}

int main() {
  hors_hp_t hors_hp;
  hors_keys_t hors_keys;
  hors_new_hp(&hors_hp, "./config");
  hors_keygen(&hors_keys, &hors_hp);

  hors_signer_t signer = hors_new_signer(&hors_hp, &hors_keys);
  hors_signature_t signature;
  signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->l));
  hors_sign(&signature, &signer, "qweqweqwe", 9);

  hors_verifier_t verifier = hors_new_verifier(hors_keys.pk);

  if (hors_verify(&verifier, &hors_hp, &signature, "qweqweqwe", 9) == HORS_SIGNATURE_ACCEPTED)
    printf("signature is valid\n");
  else
    printf("signature is not valid\n");
}
