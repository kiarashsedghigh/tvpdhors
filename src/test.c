#include <stdio.h>
#include <openssl/bn.h>

int main() {
  // Declare a BIGNUM variable
  BIGNUM *bigNum = BN_new();

  if (!bigNum) {
    fprintf(stderr, "Error: Unable to initialize BIGNUM\n");
    return 1;
  }

  // Assign an integer value to the BIGNUM variable
  int integerValue = 123;
  BN_set_word(bigNum, integerValue);

  // Print the BIGNUM value
  printf("BigNum: ");
  BN_print_fp(stdout, bigNum);
  printf("\n");

  // Free memory
  BN_free(bigNum);

  return 0;
}
