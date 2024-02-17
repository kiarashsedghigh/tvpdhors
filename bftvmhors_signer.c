#include <bftvmhors/bftvmhors.h>
#include <bftvmhors/bits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#define CNT 10000
#include <bftvmhors/prng.h>
int main() {

    double keygen_time = 0;
    double sign_time = 0;
    double verify_time = 0;


    bftvmhors_hp_t bftvmhors_hp;
    bftvmhors_keys_t bftvmhors_keys;

    bftvmhors_new_hp(&bftvmhors_hp, "./config_sample");
    printf("------------\n");
    printf("t: %d\n", bftvmhors_hp.t);
    printf("k: %d\n", bftvmhors_hp.k);
    printf("l: %d\n", bftvmhors_hp.l);
    printf("lpk: %d\n", bftvmhors_hp.lpk);
    printf("h: %d\n", bftvmhors_hp.ohbf_hp.num_of_mod_operations);
    printf("m: %d\n", bftvmhors_hp.ohbf_hp.actual_size);


    for (int i = 0; i < CNT; i++) {
        bftvmhors_keygen(&bftvmhors_keys, &bftvmhors_hp);
        keygen_time += BFTVMHORS_KEYGEN_TIME;
    }

    //    for(int i=0;i<20;i++)
//        printf("%0.2x",bftvmhors_keys.sk_seeds[i]);
//    exit(0);
////
//#ifdef TVMULTITHREAD
//    u8* current_state_sks;
//    prng_chacha20(&current_state_sks, bftvmhors_keys.sk_seeds, BITS_2_BYTES(bftvmhors_hp.sk_seed_len),BITS_2_BYTES(bftvmhors_hp.l) * bftvmhors_hp.t);
//    for(int i=0;i<10;i++)
//        printf("%0.2x",bftvmhors_keys.sk_seeds[i]);
//
//    printf("\n");
//    for(int i=0;i<bftvmhors_hp.t;i++){
//        for(int j=0;j<BITS_2_BYTES(bftvmhors_hp.l);j++){
//            printf("%0.2x",current_state_sks[i*8 + j]);
//        }
//            printf("\n");
//    }
//    printf("%0.2x\n", bftvmhors_keys);
//#endif

    bftvmhors_signer_t signer = bftvmhors_new_signer(&bftvmhors_hp, &bftvmhors_keys);
    bftvmhors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->l));


    for(int i=0;i<CNT;i++) {

        /* Signer */

        bftvmhors_sign(&signature, &signer, "aaa", 3);
        sign_time += BFTVMHORS_SIGN_TIME;

        bftvmhors_verifier_t verifier = bftvmhors_new_verifier(&bftvmhors_keys.pk);

        /* Verifier */
        bftvmhors_verify(&verifier, &bftvmhors_hp, &signature, "aaa", 3);
        verify_time += BFTVMHORS_VERIFY_TIME;
//
        if (bftvmhors_verify(&verifier, &bftvmhors_hp, &signature, "aaa", 3)==BFTVMHORS_SIGNATURE_ACCEPTED)
            printf("signature is valid\n");
        else
            printf("signature is not valid\n");

    }

    printf("------------\n");
    printf("t: %d\n", bftvmhors_hp.t);
    printf("k: %d\n", bftvmhors_hp.k);
    printf("l: %d\n", bftvmhors_hp.l);
    printf("lpk: %d\n", bftvmhors_hp.lpk);
    printf("h: %d\n", bftvmhors_hp.ohbf_hp.num_of_mod_operations);
    printf("m: %d\n", bftvmhors_hp.ohbf_hp.required_size);

    printf("Act Size: %d\n",bftvmhors_hp.ohbf_hp.actual_size);
    printf("BFTVMHORS Keygen Time: %0.12f\n", keygen_time/CNT * 1000000);
    printf("BFTVMHORS Sign Time: %0.12f\n", sign_time/CNT * 1000000);
    printf("BFTVMHORS Verify Time: %0.12f\n", verify_time/CNT * 1000000);

    bftvmhors_destroy_hp(&bftvmhors_hp);
}

