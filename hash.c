//#include "hash.h"
//
//#include <stdio.h>
//
//#include <openssl/bn.h>
//
//int main(){
//
//        u8 buffer[100];
//
//        int s = hash_sha2_256(buffer, "d", 1);
////
//
//    BIGNUM *a = BN_new();
//    BIGNUM *b = BN_new();
//    BIGNUM *m = BN_new();
//    BIGNUM *result = BN_new();
//
//    BIGNUM *new_hash = BN_new();
//
//    // Initialize values for a, b, and m
//    BN_bin2bn(buffer, s, new_hash);
//    BN_dec2bn(&b, "4");
//    BN_hex2bn(&m, "100"); // Modulus
//
//    // Perform a % m and store the result in 'result'
//    BN_mod(result, new_hash, m, BN_CTX_new());
//
//    // Print the result
//    char *result_str = BN_bn2dec(result);
//    printf("Result of %s mod %s is %s\n", BN_bn2dec(a), BN_bn2dec(m), result_str);
//
//
////    BIGNUM * hash = BN_new();
////    BN_dec2bn(&hash,"12");
////    BIGNUM * rem = BN_new();
////
////    BIGNUM * de = BN_new();
////    BN_dec2bn(&hash,"5");
////
////    BN_CTX * ctx = BN_CTX_new();
////
////    BN_mod(rem, hash, de,ctx);
////
////    printf(">> %s", BN_bn2dec(rem));
//////    int BN_mod(BIGNUM *rem, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
////
//////    printf("%s\n", buffer);
//
//}
//
//
//
//
//
//
