#ifndef BFTVMHORS_BFTVMHORS_H
#define BFTVMHORS_BFTVMHORS_H

#include <bftvmhors/bf.h>
#include <bftvmhors/types.h>

#define BFTVMHORS_NEW_HP_SUCCESS 0
#define BFTVMHORS_NEW_HP_FAILED 1

#define BFTVMHORS_KEYGEN_SUCCESS 0
#define BFTVMHORS_KEYGEN_FAILED 1

#define BFTVMHORS_SIGNATURE_ACCEPTED 0
#define BFTVMHORS_SIGNATURE_REJECTED 1

#define BFTVMHORS_SIGNING_SUCCESS 0
#define BFTVMHORS_SIGNING_FAILED 1

#define BFTVMHORS_REJECTION_SAMPLING_SUCCESS 0
#define BFTVMHORS_REJECTION_SAMPLING_FAILED 1

#define BFTVMHORS_REJECTION_SAMPLING_DONE 0
#define BFTVMHORS_REJECTION_SAMPLING_NOT_DONE 1

/// Implements the hyper parameters of BFTVMHORS
typedef struct bftvmhors_hp {
  u32 N;                     // Number of messages to be signed
  u32 k;                     // k parameter of the HORS signature
  u32 t;                     // t parameter of the HORS signature
  u32 l;                     // l parameter of the HORS signature
  u8 *seed_file;             // Seed file
  u32 sk_seed_len;           // Length of private key seeds in bits
  sbf_hp_t sbf_hp;           // Hyper parameters of the underlying Standard Bloom Filter (SBF)
  u8 do_rejection_sampling;  // Do/Don't perform rejection sampling
} bftvmhors_hp_t;

/// Implements the BFTVMHORS keys
typedef struct bftvmhors_keys {
  u8 *seed;
  u8 *sk_seeds;
  sbf_t pk;
  u32 num_of_keys;
} bftvmhors_keys_t;

/// Implements the BFTVMHORS signature
typedef struct bftvmhors_signature {
  u8 *signature;
  u32 rejection_sampling_counter;
} bftvmhors_signature_t;

/// Implements the BFTVMHORS signer
typedef struct bftvmhors_signer {
  u32 state;
  bftvmhors_keys_t *keys;
  bftvmhors_hp_t *hp;
} bftvmhors_signer_t;

/// Implements the BFTVMHORS verifier
typedef struct bftvmhors_verifier {
  u32 state;
  sbf_t *pk;
} bftvmhors_verifier_t;

/// Creates hyper parameters for the BFTVMHORS
/// \param new_hp Pointer to the hyper parameter variable
/// \param config_file Name/Path of the config file
/// \return 0 if parsing the config file is successful, 1 otherwise
u32 bftvmhors_new_hp(bftvmhors_hp_t *new_hp, const u8 *config_file);

/// Destroyes the hyper parameter struct
/// \param bftvmhors_hp Pointer to the hyper parameter struct
void bftvmhors_destroy_hp(bftvmhors_hp_t *bftvmhors_hp);

/// Generates the BFTVMHORS keys
/// \param keys Pointer to the BFTVMHORS key struct
/// \param hp Pointer to the BFTVMHORS hyper parameter struct
/// \return 0 if successful, 1 otherwise
u32 bftvmhors_keygen(bftvmhors_keys_t *keys, bftvmhors_hp_t *hp);

#endif
