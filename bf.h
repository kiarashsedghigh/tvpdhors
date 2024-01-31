#ifndef BFTVMHORS_BF_H
#define BFTVMHORS_BF_H

#include "types.h"


#define SBF_DEF_SIZE 1024
#define SBF_DEF_NUM_HASH_FUNCS 64
#define SBF_DEF_HASH_FUNCTION "mm"

/// Implements the Standard Bloom Filter (SBF) hyper parameters (HP)
struct sbf_hp{
    u32 size;               // Size of the SBF
    u32 num_hash_functions;     // Number of hash functions to be used
    u8 * hash_family;           // Family of the functions to be used for hashing. #TODO Talk about the list
}sbf_hp_default = {SBF_DEF_SIZE, SBF_DEF_NUM_HASH_FUNCS, SBF_DEF_HASH_FUNCTION};

typedef struct sbf_hp sbf_hp_t;


/// Creates the hyper parameters of the SBF
/// \param size Size of the SBF. (0 for default)
/// \param num_hash_functions Number of hash functions to be used. (0 for default)
/// \param hash_family Type of the hash function to be used. (NULL for default)
/// \return SBF hyper parameter struct (sbf_hp_t)
sbf_hp_t sbf_new_hp(u32 size, u32 num_hash_functions, u8 * hash_family);



/// Standard Bloom Filter (SBF) implementation
typedef struct sbf{
    u8 * bv;    // The SBF bit vector
    void (** hash_functions)(u32) ;     // Array of hash functions for the SBF
    u32 size;               // Size of the SBF
    u32 num_hash_functions;     // Number of hash functions to be used
}sbf_t;


/// Creates a new SBF with the given hyper parameters
/// \param sbf_hp The SBF hyper parameters
/// \return New SBF (sbf_t)
sbf_t sbf_creat(sbf_hp_t * sbf_hp);


/// Destroys the given SBF
/// \param sbf Target SBF to be destroyed
void sbf_destroy(sbf_t * sbf);


#endif

