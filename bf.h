#ifndef BFTVMHORS_BF_H
#define BFTVMHORS_BF_H

#include "types.h"


#define SBF_ELEMENT_EXISTS 0
#define SBF_ELEMENT_ABSENTS 1


/// Implements the Standard Bloom Filter (SBF) hyper parameters (HP)
/// List of hash functions supported are:
///         ltc_sha256
///         openssl_sha256
///         jenkins_oaat
///         fnv64_0
///         fnv64_1
///         fnv64_1a
typedef struct sbf_hp {
  u32 size;                // Size of the SBF
  u32 num_hash_functions;  // Number of hash functions to be used
  u8 *hash_family;  // Family of the functions to be used for hashing. #TODO Talk about the list
} sbf_hp_t;

/// Creates the hyper parameters of the SBF
/// \param size Size of the SBF. (0 for default)
/// \param num_hash_functions Number of hash functions to be used. (0 for default)
/// \param hash_family Type of the hash function to be used. (NULL for default)
/// \return SBF hyper parameter struct (sbf_hp_t)
sbf_hp_t sbf_new_hp(u32 size, u32 num_hash_functions, const u8 *hash_family);

/// Standard Bloom Filter (SBF) implementation
typedef struct sbf {
  u8 *bv;                                         // The SBF bit vector
  u32 (**hash_functions)(u8 *, const u8 *, u64);  // Array of hash functions for the SBF
  u32 size;                                       // Size of the SBF
  u32 num_hash_functions;                         // Number of hash functions to be used
} sbf_t;

/// Creates a new SBF with the given hyper parameters
/// \param sbf_hp The SBF hyper parameters
/// \return New SBF (sbf_t)
u32 sbf_create(sbf_t *sbf, const sbf_hp_t *sbf_hp);

/// Destroys the given SBF
/// \param sbf Target SBF to be destroyed
void sbf_destroy(const sbf_t *sbf);

/// Insert the input to the passed SBF
/// \param sbf The SBF we want to insert into
/// \param input The input to be inserted into the SBF
/// \param length The length of the input
void sbf_insert(const sbf_t *sbf, const u8 *input, u64 length);

/// Checks if an element is in the SBF
/// \param sbf The SBF we want to check the element existence in
/// \param input The input to be inserted into the SBF
/// \param length The length of the input
/// \return Returns 1 if the element exists in the SBF, otherwise, 0
u32 sbf_check(const sbf_t *sbf, const u8 *input, u64 input_length);

#endif