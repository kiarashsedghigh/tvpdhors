#include <bftvmhors/hash.h>
#include <bftvmhors/prng.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define INPUT_DATA_SIZE_8 1
#define INPUT_DATA_SIZE_16 2
#define INPUT_DATA_SIZE_32 4
#define INPUT_DATA_SIZE_64 8
#define INPUT_DATA_SIZE_128 16
#define INPUT_DATA_SIZE_256 32

#define ITERATION_COUNT 1000000


/// Computes the time of the passed hash function
/// \param hash_function Target hash function
/// \param hash_output Hash output buffer
/// \param input Hash input buffer
/// \param length Hash input size
/// \return Time of the hash in seconds
double get_hash_time(u32 (*hash_function)(u8 *, const u8 *, u64), u8 * hash_output, const u8 * input, u64 length ){

  struct timeval begin, end;
  gettimeofday(&begin, 0);

  hash_function(hash_output, input, length);

  gettimeofday(&end, 0);
  long seconds = end.tv_sec - begin.tv_sec;
  long microseconds = end.tv_usec - begin.tv_usec;
  double elapsed = seconds + microseconds*1e-6;
  return elapsed;
}


void hash_test(u32 (*hash_function)(u8 *, const u8 *, u64), u8 * hash_function_name){

  u8 hash_output[HASH_MAX_LENGTH_THRESHOLD];

  double total_sec_input_8 = 0;
  double total_sec_input_16 = 0;
  double total_sec_input_32 = 0;
  double total_sec_input_64 = 0;
  double total_sec_input_128 = 0;
  double total_sec_input_256 = 0;


  for(u32 i=0; i<ITERATION_COUNT; i++){

    /* Generate random data of different sizes */
    u8 * input_8; prng_chacha20(&input_8, &i, 4, INPUT_DATA_SIZE_8);
    u8 * input_16; prng_chacha20(&input_16, &i, 4, INPUT_DATA_SIZE_16);
    u8 * input_32; prng_chacha20(&input_32, &i, 4, INPUT_DATA_SIZE_32);
    u8 * input_64; prng_chacha20(&input_64, &i, 4, INPUT_DATA_SIZE_64);
    u8 * input_128; prng_chacha20(&input_128, &i, 4, INPUT_DATA_SIZE_128);
    u8 * input_256; prng_chacha20(&input_256, &i, 4, INPUT_DATA_SIZE_256);

    total_sec_input_8 += get_hash_time(hash_function, hash_output, input_8, INPUT_DATA_SIZE_8);
    total_sec_input_16 += get_hash_time(hash_function, hash_output, input_16, INPUT_DATA_SIZE_16);
    total_sec_input_32 += get_hash_time(hash_function, hash_output, input_32, INPUT_DATA_SIZE_32);
    total_sec_input_64 += get_hash_time(hash_function, hash_output, input_64, INPUT_DATA_SIZE_64);
    total_sec_input_128 += get_hash_time(hash_function, hash_output, input_128, INPUT_DATA_SIZE_128);
    total_sec_input_256 += get_hash_time(hash_function, hash_output, input_256, INPUT_DATA_SIZE_256);

    free(input_8);
    free(input_16);
    free(input_32);
    free(input_64);
    free(input_128);
    free(input_256);

  }
  printf("%s--------------- 1000000 times --------------- \n", hash_function_name);
  printf("8-bit: %.8f seconds\n", total_sec_input_8/ITERATION_COUNT);
  printf("16-bit: %.8f seconds\n", total_sec_input_16/ITERATION_COUNT);
  printf("32-bit: %.8f seconds\n", total_sec_input_32/ITERATION_COUNT);
  printf("64-bit: %.8f seconds\n", total_sec_input_64/ITERATION_COUNT);
  printf("128-bit: %.8f seconds\n", total_sec_input_128/ITERATION_COUNT);
  printf("256-bit:  %.8f seconds\n\n", total_sec_input_256/ITERATION_COUNT);
}



int main() {

    /* LTC */
    hash_test(ltc_hash_sha2_256,"ltc_sha256");

    /* Openssl */
    hash_test(openssl_hash_sha1,"openssl_sha1");
    hash_test(openssl_hash_sha2_256,"openssl_sha2_256");
    hash_test(openssl_hash_md5,"openssl_md5");

    /* FNV */
    hash_test(fnv64_0,"fnv64_0");
    hash_test(fnv64_1,"fnv64_1");
    hash_test(fnv64_1a,"fnv64_1a");

    /* Jenkins */
    hash_test(jenkins_oaat,"jenkins_oaat");

    /* Siphash */
    hash_test(jp_aumasson_siphash,"jp_aumasson_siphash");

    /* Blake */
    hash_test(blake2b_256,"blake2b_256");
    hash_test(blake2b_384,"blake2b_384");
    hash_test(blake2b_512,"blake2b_512");
    hash_test(blake2s_128,"blake2s_128");
    hash_test(blake2s_160,"blake2s_160");
    hash_test(blake2s_224,"blake2s_224");
    hash_test(blake2s_256,"blake2s_256");

    /* XXHash */
    hash_test(xxhash_32,"xxhash_32");
    hash_test(xxhash_64,"xxhash_64");
    hash_test(xxhash3_64,"xxhash3_64");
    hash_test(xxhash3_128,"xxhash3_128");

    /* Murmur2 */
    hash_test(murmur2_32,"murmur_32");

    return 0;
}
