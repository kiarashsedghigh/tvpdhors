#include <bftvmhors/types.h>
#include <string.h>

u32 jenkins_oaat(u8 * hash_output, const u8 * key, u64 length) {
    u64 i = 0;
    u32 hash = 0;
    while (i != length) {
        hash += key[i++];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    memcpy(hash_output, &hash, sizeof(u32));

    return sizeof(u32);
}


