#include <bftvmhors/bftvmhors.h>
#include <bftvmhors/bits.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    bftvmhors_hp_t bftvmhors_hp;
    bftvmhors_keys_t bftvmhors_keys;
    bftvmhors_new_hp(&bftvmhors_hp, "./config");
    bftvmhors_keygen(&bftvmhors_keys, &bftvmhors_hp);

    /* Signer */
    bftvmhors_signer_t signer = bftvmhors_new_signer(&bftvmhors_hp, &bftvmhors_keys);
    bftvmhors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->l));
    bftvmhors_sign(&signature, &signer, "aaa", 3);

    /* Verifier */
    bftvmhors_verifier_t verifier = bftvmhors_new_verifier(&bftvmhors_keys.pk);

    if (bftvmhors_verify(&verifier, &bftvmhors_hp, &signature, "aqa", 3)==BFTVMHORS_SIGNATURE_ACCEPTED)
        printf("signature is valid\n");
    else
        printf("signature is not valid\n");

    bftvmhors_destroy_hp(&bftvmhors_hp);
}

