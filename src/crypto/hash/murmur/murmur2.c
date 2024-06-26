#include <bftvmhors/types.h>
#include <stdint.h>

#include <string.h>

// TODO check the implementation
u32 murmur2_32(u8 * hash_output, const u8 * input , u64 length){
  // 'm' and 'r' are mixing constants generated offline.
  // They're not really 'magic', they just happen to work well.

  const uint32_t m = 0x5bd1e995;
  const int r = 24;

  // Initialize the hash to a 'random' value

  uint32_t h = length;

  // Mix 4 bytes at a time into the hash

  const unsigned char * data = (const unsigned char *)input;

  while(length >= 4)
  {
    uint32_t k = *(uint32_t*)data;

    k *= m;
    k ^= k >> r;
    k *= m;

    h *= m;
    h ^= k;

    data += 4;
    length -= 4;
  }

  // Handle the last few bytes of the input array

  switch(length)
  {
  case 3: h ^= data[2] << 16;
  case 2: h ^= data[1] << 8;
  case 1: h ^= data[0];
    h *= m;
  };

  // Do a few final mixes of the hash to ensure the last few
  // bytes are well-incorporated.

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;

  memcpy(hash_output, &h, sizeof(uint32_t));
  return sizeof(uint32_t);
}


uint64_t murmur2_64 ( const void * key, int len, uint64_t seed )
{
//  const uint64_t m = 0xc6a4a7935bd1e995;
//  const int r = 47;
//
//  uint64_t h = seed ^ (len * m);
//
//  const uint64_t * data = (const uint64_t *)key;
//  const uint64_t * end = data + (len/8);
//
//  while(data != end)
//  {
//    uint64_t k = *data++;
//
//    k *= m;
//    k ^= k >> r;
//    k *= m;
//
//    h ^= k;
//    h *= m;
//  }
//
//  const unsigned char * data2 = (const unsigned char*)data;
//
//  switch(len & 7){
//  case 7: h ^= uint64_t(data2[6]) << 48;
//    // Fall-through intentionally
//  case 6: h ^= uint64_t(data2[5]) << 40;
//    // Fall-through intentionally
//  case 5: h ^= uint64_t(data2[4]) << 32;
//    // Fall-through intentionally
//  case 4: h ^= uint64_t(data2[3]) << 24;
//    // Fall-through intentionally
//  case 3: h ^= uint64_t(data2[2]) << 16;
//    // Fall-through intentionally
//  case 2: h ^= uint64_t(data2[1]) << 8;
//    // Fall-through intentionally
//  case 1: h ^= uint64_t(data2[0]);
//    h *= m;
//    break;
//  default: // Handle the case when len & 7 is not 1 to 7
//  };
//
//  h ^= h >> r;
//  h *= m;
//  h ^= h >> r;

  return 0;
}



