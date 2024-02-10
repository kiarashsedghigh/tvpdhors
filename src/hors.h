#ifndef BFTVMHORS_HORS_H
#define BFTVMHORS_HORS_H

#include <bftvmhors/types.h>

double hors_get_keygen_time();
double hors_get_sign_time();
double hors_get_verify_time();

#define HORS_KEYGEN_TIME hors_get_keygen_time()
#define HORS_SIGN_TIME hors_get_sign_time()
#define HORS_VERIFY_TIME hors_get_verify_time()


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
  u32 lpk;                    // Size of the public key portion
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



u32 hors_new_hp(hors_hp_t* new_hp, const u8* config_file);
u32 hors_verify(hors_verifier_t* verifier, hors_hp_t* hp, hors_signature_t* signature, u8* message, u64 message_len);
hors_verifier_t hors_new_verifier(u8* pk);
u32 hors_sign(hors_signature_t* signature, hors_signer_t* signer, u8* message, u64 message_len);
hors_signer_t hors_new_signer(hors_hp_t* hp, hors_keys_t* keys);
u32 hors_keygen(hors_keys_t* keys, hors_hp_t* hp);







#endif