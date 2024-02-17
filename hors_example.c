#include <bftvmhors/hors.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/debug.h>
#include <bftvmhors/file.h>
#include <stdlib.h>

#define ITERATION_CNT 10000

int main(int argc, char **argv) {

    if (argc<3){
        debug("Usage:  ./hors CONFIG_FILE_PATH MESSAGE_FILE_PATH", DEBUG_ERR);
        return 1;
    }
    debug("Parameters of the config_sample file should be chosen carefully (t, k, multi-thread...), otherwise, the output can be unexpected", DEBUG_WARNING);

    /* Hyper parameters and keys */
    hors_hp_t hp;
    hors_keys_t keys;

    debug("Reading the config file...", DEBUG_INF);
    if (hors_new_hp(&hp, argv[1]) == HORS_NEW_HP_FAILED)
        return 1;

    /* HORS key generation */
    debug("Generating private and public keys...", DEBUG_INF);
    if (hors_keygen(&keys, &hp) == HORS_KEYGEN_FAILED)
        return 1;

    /* Signer */
    debug("New signer is created", DEBUG_INF);
    hors_signer_t signer;
    hors_new_signer(&signer, &hp, &keys);
    hors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->lpk));

    /* Reading the message */
    u8 * message;
    u32 message_len;
    if ((message_len = read_file(&message, argv[2])) == FILE_OPEN_ERROR)
        return 1;

    hors_sign(&signature, &signer, message, message_len);
    debug("Signature is ready", DEBUG_INF);


//    double sign_time = 0;
//    for(int i=0;i<1000;i++) {
//        hors_sign(&signature, &signer, message, message_len);
//        sign_time += HORS_SIGN_TIME;
//    }
////
//    printf("Hors Sign Time: %0.12f\n", sign_time/1000* 1000000);




    /* Verifier */
    debug("New verifier is created", DEBUG_INF);
    hors_verifier_t verifier;
    hors_new_verifier(&verifier, keys.pk);

    if (hors_verify(&verifier, &hp, &signature, message, message_len) == HORS_SIGNATURE_ACCEPTED)
        debug("Verification: Signature is valid", DEBUG_INF);
    else
        debug("Verification: Signature is (not) valid", DEBUG_INF);


    debug("Deleting hyper parameter and the keys", DEBUG_INF);
    hors_destroy_hp(&hp);
    hors_destroy_keys(&keys);
}


