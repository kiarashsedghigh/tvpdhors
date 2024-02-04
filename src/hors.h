#ifndef BFTVMHORS_HORS_H
#define BFTVMHORS_HORS_H

#include <bftvmhors/types.h>

#define HORS_NEW_HP_SUCCESS 0
#define HORS_NEW_HP_FAILED 1

#define HORS_KEYGEN_SUCCESS 0
#define HORS_KEYGEN_FAILED 1

#define HORS_SIGNATURE_ACCEPTED 0
#define HORS_SIGNATURE_REJECTED 1

#define HORS_SIGNING_SUCCESS 0
#define HORS_SIGNING_FAILED 1

#define HORS_REJECTION_SAMPLING_SUCCESS 0
#define HORS_REJECTION_SAMPLING_FAILED 1

#define HORS_REJECTION_SAMPLING_DONE 0
#define HORS_REJECTION_SAMPLING_NOT_DONE 1


/// Implements the hyper parameters of HORS
typedef struct hors_hp{
  u32 N;        // Number of messages to be signed
  u32 k;                      // k parameter of the HORS signature
  u32 t;                      // t parameter of the HORS signature
  u32 l;                      // l parameter of the HORS signature
  u8 * seed_file;             // Seed file
  u8 do_rejection_sampling;   // Do/Don't perform rejection sampling
}hors_hp_t;


/// Implements the HORS keys
typedef struct hors_keys{
  u8 * sk;
  u8 * pk;
}hors_keys_t;

/// Implements the HORS signature
typedef struct hors_signature {
  u8 * signature;
  u32 rejection_sampling_counter;
}hors_signature_t;


/// Implements the HORS signer
typedef struct hors_signer{
  u32 state;    // Not necessarily used. It is here for compatibility
  hors_keys_t * keys;
  hors_hp_t * hp;
}hors_signer_t;

/// Implements the HORS verifier
typedef struct hors_verifier{
  u32 state;    // Not necessarily used. It is here for compatibility
  u8 * pk;
}hors_verifier_t;





#endif