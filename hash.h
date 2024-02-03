#ifndef BFTVMHORS_HASH_H
#define BFTVMHORS_HASH_H

#include <bftvmhors/types.h>

/// This defines the maximum hash length (in Bytes) of all the hash functions supported
#define HASH_MAX_LENGTH_THRESHOLD 80

/// Computes the hash value based on the SHA2-256
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 hash_sha2_256(u8 * hash_output, const u8 * input , u64 length);

#endif