#include <bftvmhors/types.h>
#include <string.h>



#define FNV_PRIME_64 1099511628211U
#define FNV_OFFSET_64 14695981039346656037U


u32 fnv64_0(u8 * hash_output, const u8 * input , u64 length){
    u32 hash = 0;
    for(u32 i = 0; i < length; i++){
        hash = hash * FNV_PRIME_64;
        hash = hash ^ input[i];
    }
    memcpy(hash_output, &hash, sizeof(u64));
    return sizeof(u64);
}

u32 fnv64_1(u8 * hash_output, const u8 * input , u64 length){
    u32 hash = FNV_OFFSET_64;
    for(u32 i = 0; i < length; i++){
        hash = hash * FNV_PRIME_64;
        hash = hash ^ input[i];
    }
    memcpy(hash_output, &hash, sizeof(u64));
    return sizeof(u64);
}


u32 fnv64_1a(u8 * hash_output, const u8 * input , u64 length){
    u32 hash = FNV_OFFSET_64;
    for(u32 i = 0; i < length; i++){
        hash = hash ^ input[i];
        hash = hash * FNV_PRIME_64;
    }
    memcpy(hash_output, &hash, sizeof(u64));
    return sizeof(u64);
}
