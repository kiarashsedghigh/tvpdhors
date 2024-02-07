#include <bftvmhors/hash.h>
#include <bftvmhors/prng.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define INPUT_DATA_SIZE_1 1
#define INPUT_DATA_SIZE_2 2
#define INPUT_DATA_SIZE_4 4
#define INPUT_DATA_SIZE_8 8
#define INPUT_DATA_SIZE_16 16
#define INPUT_DATA_SIZE_32 32
#define INPUT_DATA_SIZE_64 64
#define INPUT_DATA_SIZE_128 128
#define INPUT_DATA_SIZE_256 256
#define INPUT_DATA_SIZE_512 512

#define INPUT_DATA_SIZE_1K 1024
#define INPUT_DATA_SIZE_2K 2048
#define INPUT_DATA_SIZE_4K 4096
#define INPUT_DATA_SIZE_8K 8192
#define INPUT_DATA_SIZE_16K 16384
#define INPUT_DATA_SIZE_32K 32768
#define INPUT_DATA_SIZE_64K 65536
#define INPUT_DATA_SIZE_128K 131072
#define INPUT_DATA_SIZE_256K 262144
#define INPUT_DATA_SIZE_512K 524288

#define INPUT_DATA_SIZE_1M 1048576
#define INPUT_DATA_SIZE_2M 2097152
#define INPUT_DATA_SIZE_4M 4194304
#define INPUT_DATA_SIZE_8M 8388608
#define INPUT_DATA_SIZE_16M 16777216
#define INPUT_DATA_SIZE_32M 33554432
#define INPUT_DATA_SIZE_64M 67108864
#define INPUT_DATA_SIZE_128M 134217728
#define INPUT_DATA_SIZE_256M 268435456

#define ITERATION_COUNT 500


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

  /* Bytes */
  double total_sec_input_1 = 0;
  double total_sec_input_2 = 0;
  double total_sec_input_4 = 0;
  double total_sec_input_8 = 0;
  double total_sec_input_16 = 0;
  double total_sec_input_32 = 0;
  double total_sec_input_64 = 0;
  double total_sec_input_128 = 0;
  double total_sec_input_256 = 0;
  double total_sec_input_512 = 0;

  /* KiloBytes */
  double total_sec_input_1K = 0;
  double total_sec_input_2K = 0;
  double total_sec_input_4K = 0;
  double total_sec_input_8K = 0;
  double total_sec_input_16K = 0;
  double total_sec_input_32K = 0;
  double total_sec_input_64K = 0;
  double total_sec_input_128K = 0;
  double total_sec_input_256K = 0;
  double total_sec_input_512K = 0;

  /* MegaBytes */
  double total_sec_input_1M = 0;
  double total_sec_input_2M = 0;
  double total_sec_input_4M = 0;
  double total_sec_input_8M = 0;
  double total_sec_input_16M = 0;
  double total_sec_input_32M = 0;
  double total_sec_input_64M = 0;
  double total_sec_input_128M = 0;
  double total_sec_input_256M = 0;

  int i=0;

  /* Generate random data of different sizes */
  u8 * input_1; prng_chacha20(&input_1, &i, 4, INPUT_DATA_SIZE_1);
  u8 * input_2; prng_chacha20(&input_2, &i, 4, INPUT_DATA_SIZE_2);
  u8 * input_4; prng_chacha20(&input_4, &i, 4, INPUT_DATA_SIZE_4);
  u8 * input_8; prng_chacha20(&input_8, &i, 4, INPUT_DATA_SIZE_8);
  u8 * input_16; prng_chacha20(&input_16, &i, 4, INPUT_DATA_SIZE_16);
  u8 * input_32; prng_chacha20(&input_32, &i, 4, INPUT_DATA_SIZE_32);
  u8 * input_64; prng_chacha20(&input_64, &i, 4, INPUT_DATA_SIZE_64);
  u8 * input_128; prng_chacha20(&input_128, &i, 4, INPUT_DATA_SIZE_128);
  u8 * input_256; prng_chacha20(&input_256, &i, 4, INPUT_DATA_SIZE_256);
  u8 * input_512; prng_chacha20(&input_512, &i, 4, INPUT_DATA_SIZE_512);


  u8 * input_1K; prng_chacha20(&input_1K, &i, 4, INPUT_DATA_SIZE_1K);
  u8 * input_2K; prng_chacha20(&input_2K, &i, 4, INPUT_DATA_SIZE_2K);
  u8 * input_4K; prng_chacha20(&input_4K, &i, 4, INPUT_DATA_SIZE_4K);
  u8 * input_8K; prng_chacha20(&input_8K, &i, 4, INPUT_DATA_SIZE_8K);
  u8 * input_16K; prng_chacha20(&input_16K, &i, 4, INPUT_DATA_SIZE_16K);
  u8 * input_32K; prng_chacha20(&input_32K, &i, 4, INPUT_DATA_SIZE_32K);
  u8 * input_64K; prng_chacha20(&input_64K, &i, 4, INPUT_DATA_SIZE_64K);
  u8 * input_128K; prng_chacha20(&input_128K, &i, 4, INPUT_DATA_SIZE_128K);
  u8 * input_256K; prng_chacha20(&input_256K, &i, 4, INPUT_DATA_SIZE_256K);
  u8 * input_512K; prng_chacha20(&input_512K, &i, 4, INPUT_DATA_SIZE_512K);

  u8 * input_1M; prng_chacha20(&input_1M, &i, 4, INPUT_DATA_SIZE_1M);
  u8 * input_2M; prng_chacha20(&input_2M, &i, 4, INPUT_DATA_SIZE_2M);
  u8 * input_4M; prng_chacha20(&input_4M, &i, 4, INPUT_DATA_SIZE_4M);
  u8 * input_8M; prng_chacha20(&input_8M, &i, 4, INPUT_DATA_SIZE_8M);
  u8 * input_16M; prng_chacha20(&input_16M, &i, 4, INPUT_DATA_SIZE_16M);
  u8 * input_32M; prng_chacha20(&input_32M, &i, 4, INPUT_DATA_SIZE_32M);
  u8 * input_64M; prng_chacha20(&input_64M, &i, 4, INPUT_DATA_SIZE_64M);
  u8 * input_128M; prng_chacha20(&input_128M, &i, 4, INPUT_DATA_SIZE_128M);
  u8 * input_256M; prng_chacha20(&input_256M, &i, 4, INPUT_DATA_SIZE_256M);

//  printf("Data Generated\n");

  for(u32 i=0; i< ITERATION_COUNT; i++){

    total_sec_input_1 += get_hash_time(hash_function, hash_output, input_1, INPUT_DATA_SIZE_1);
    total_sec_input_2 += get_hash_time(hash_function, hash_output, input_2, INPUT_DATA_SIZE_2);
    total_sec_input_4 += get_hash_time(hash_function, hash_output, input_4, INPUT_DATA_SIZE_4);
    total_sec_input_8 += get_hash_time(hash_function, hash_output, input_8, INPUT_DATA_SIZE_8);
    total_sec_input_16 += get_hash_time(hash_function, hash_output, input_16, INPUT_DATA_SIZE_16);
    total_sec_input_32 += get_hash_time(hash_function, hash_output, input_32, INPUT_DATA_SIZE_32);
    total_sec_input_64 += get_hash_time(hash_function, hash_output, input_64, INPUT_DATA_SIZE_64);
    total_sec_input_128 += get_hash_time(hash_function, hash_output, input_128, INPUT_DATA_SIZE_128);
    total_sec_input_256 += get_hash_time(hash_function, hash_output, input_256, INPUT_DATA_SIZE_256);
    total_sec_input_512 += get_hash_time(hash_function, hash_output, input_512, INPUT_DATA_SIZE_512);

    total_sec_input_1K += get_hash_time(hash_function, hash_output, input_1K, INPUT_DATA_SIZE_1K);
    total_sec_input_2K += get_hash_time(hash_function, hash_output, input_2K, INPUT_DATA_SIZE_2K);
    total_sec_input_4K += get_hash_time(hash_function, hash_output, input_4K, INPUT_DATA_SIZE_4K);
    total_sec_input_8K += get_hash_time(hash_function, hash_output, input_8K, INPUT_DATA_SIZE_8K);
    total_sec_input_16K += get_hash_time(hash_function, hash_output, input_16K, INPUT_DATA_SIZE_16K);
    total_sec_input_32K += get_hash_time(hash_function, hash_output, input_32K, INPUT_DATA_SIZE_32K);
    total_sec_input_64K += get_hash_time(hash_function, hash_output, input_64K, INPUT_DATA_SIZE_64K);
    total_sec_input_128K += get_hash_time(hash_function, hash_output, input_128K, INPUT_DATA_SIZE_128K);
    total_sec_input_256K += get_hash_time(hash_function, hash_output, input_256K, INPUT_DATA_SIZE_256K);
    total_sec_input_512K += get_hash_time(hash_function, hash_output, input_512K, INPUT_DATA_SIZE_512K);

    total_sec_input_1M += get_hash_time(hash_function, hash_output, input_1M, INPUT_DATA_SIZE_1M);
    total_sec_input_2M += get_hash_time(hash_function, hash_output, input_2M, INPUT_DATA_SIZE_2M);
    total_sec_input_4M += get_hash_time(hash_function, hash_output, input_4M, INPUT_DATA_SIZE_4M);
    total_sec_input_8M += get_hash_time(hash_function, hash_output, input_8M, INPUT_DATA_SIZE_8M);
    total_sec_input_16M += get_hash_time(hash_function, hash_output, input_16M, INPUT_DATA_SIZE_16M);
    total_sec_input_32M += get_hash_time(hash_function, hash_output, input_32M, INPUT_DATA_SIZE_32M);
    total_sec_input_64M += get_hash_time(hash_function, hash_output, input_64M, INPUT_DATA_SIZE_64M);
    total_sec_input_128M += get_hash_time(hash_function, hash_output, input_128M, INPUT_DATA_SIZE_128M);
    total_sec_input_256M += get_hash_time(hash_function, hash_output, input_256M, INPUT_DATA_SIZE_256M);


  }
  free(input_1);
  free(input_2);
  free(input_4);
  free(input_8);
  free(input_16);
  free(input_32);
  free(input_64);
  free(input_128);
  free(input_256);
  free(input_512);

  free(input_1K);
  free(input_2K);
  free(input_4K);
  free(input_8K);
  free(input_16K);
  free(input_32K);
  free(input_64K);
  free(input_128K);
  free(input_256K);
  free(input_512K);

  free(input_1M);
  free(input_2M);
  free(input_4M);
  free(input_8M);
  free(input_16M);
  free(input_32M);
  free(input_64M);
  free(input_128M);
  free(input_256M);


  printf("%s--------------- 1000000 times --------------- \n", hash_function_name);
  printf("1B: %.8f us\n", total_sec_input_1/ITERATION_COUNT );
  printf("2B: %.8f us\n", total_sec_input_2/ITERATION_COUNT);
  printf("4B: %.8f us\n", total_sec_input_4/ITERATION_COUNT);
  printf("8B: %.8f us\n", total_sec_input_8 /ITERATION_COUNT);
  printf("16B: %.8f us\n", total_sec_input_16/ITERATION_COUNT);
  printf("32B:  %.8f us\n", total_sec_input_32/ITERATION_COUNT);
  printf("64B:  %.8f us\n", total_sec_input_64/ITERATION_COUNT);
  printf("128B:  %.8f us\n", total_sec_input_128/ITERATION_COUNT);
  printf("256B:  %.8f us\n", total_sec_input_256/ITERATION_COUNT);
  printf("512B:  %.8f us\n", total_sec_input_512/ITERATION_COUNT);

  printf("1K: %.8f us\n", total_sec_input_1K/ITERATION_COUNT );
  printf("2K: %.8f us\n", total_sec_input_2K/ITERATION_COUNT);
  printf("4K: %.8f us\n", total_sec_input_4K/ITERATION_COUNT);
  printf("8K: %.8f us\n", total_sec_input_8K /ITERATION_COUNT);
  printf("16K: %.8f us\n", total_sec_input_16K/ITERATION_COUNT);
  printf("32K:  %.8f us\n", total_sec_input_32K/ITERATION_COUNT);
  printf("64K:  %.8f us\n", total_sec_input_64K/ITERATION_COUNT);
  printf("128K:  %.8f us\n", total_sec_input_128K/ITERATION_COUNT);
  printf("256K:  %.8f us\n", total_sec_input_256K/ITERATION_COUNT);
  printf("512K:  %.8f us\n", total_sec_input_512K/ITERATION_COUNT);

  printf("1M: %.8f us\n", total_sec_input_1M/ITERATION_COUNT );
  printf("2M: %.8f us\n", total_sec_input_2M/ITERATION_COUNT);
  printf("4M: %.8f us\n", total_sec_input_4M/ITERATION_COUNT);
  printf("8M: %.8f us\n", total_sec_input_8M /ITERATION_COUNT);
  printf("16M: %.8f us\n", total_sec_input_16M/ITERATION_COUNT);
  printf("32M:  %.8f us\n", total_sec_input_32M/ITERATION_COUNT);
  printf("64M:  %.8f us\n", total_sec_input_64M/ITERATION_COUNT);
  printf("128M:  %.8f us\n", total_sec_input_128M/ITERATION_COUNT);
  printf("256M:  %.8f us\n", total_sec_input_256M/ITERATION_COUNT);

}



int main() {

    /* LTC */
    hash_test(ltc_hash_sha2_256,"ltc_sha256");
//
//    /* Openssl */
    hash_test(openssl_hash_sha1,"openssl_sha1");
    hash_test(openssl_hash_sha2_256,"openssl_sha2_256");
    hash_test(openssl_hash_md5,"openssl_md5");
//
//    /* FNV */
    hash_test(fnv64_0,"fnv64_0");
    hash_test(fnv64_1,"fnv64_1");
    hash_test(fnv64_1a,"fnv64_1a");

//    /* Jenkins */
    hash_test(jenkins_oaat,"jenkins_oaat");
//
//    /* Siphash */
    hash_test(jp_aumasson_siphash,"jp_aumasson_siphash");
//
//    /* Blake */
    hash_test(blake2b_256,"blake2b_256");
    hash_test(blake2b_384,"blake2b_384");
    hash_test(blake2b_512,"blake2b_512");
    hash_test(blake2s_128,"blake2s_128");
    hash_test(blake2s_160,"blake2s_160");
    hash_test(blake2s_224,"blake2s_224");
    hash_test(blake2s_256,"blake2s_256");

//    /* XXHash */
    hash_test(xxhash_32,"xxhash_32");
    hash_test(xxhash_64,"xxhash_64");
    hash_test(xxhash3_64,"xxhash3_64");
    hash_test(xxhash3_128,"xxhash3_128");
//
//    /* Murmur2 */
    hash_test(murmur2_32,"murmur_32");

    /* Wyhash */
    hash_test(wyhash_64,"wyhash_64");


    /* Cityhash */
    hash_test(cityhash_64, "city_hash64");


    return 0;
}
