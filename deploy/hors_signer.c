#include <bftvmhors/hors.h>
#include <bftvmhors/bits.h>
#include <stdlib.h>
#include <stdio.h>


int main() {
    hors_hp_t hors_hp;
    hors_keys_t hors_keys;
    hors_new_hp(&hors_hp, "./config");
    hors_keygen(&hors_keys, &hors_hp);

    hors_signer_t signer = hors_new_signer(&hors_hp, &hors_keys);
    hors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->l));
    hors_sign(&signature, &signer, "qweqweqwe", 9);

    hors_verifier_t verifier = hors_new_verifier(hors_keys.pk);

    if (hors_verify(&verifier, &hors_hp, &signature, "qweqweqwe", 9) == HORS_SIGNATURE_ACCEPTED)
        printf("signature is valid\n");
    else
        printf("signature is not valid\n");
}


