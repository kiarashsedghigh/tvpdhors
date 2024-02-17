#include <bftvmhors/bftvmhors.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/debug.h>
#include <bftvmhors/file.h>
#include <stdlib.h>

int main(int argc, char** argv) {

    if (argc<3){
        debug("Usage:  ./hors CONFIG_FILE_PATH MESSAGE_FILE_PATH", DEBUG_ERR);
        return 1;
    }
    debug("Parameters of the config_sample file should be chosen carefully (bf, t, k, multi-thread...), otherwise, the output can be unexpected", DEBUG_WARNING);

    /* Hyper parameters and keys */
    bftvmhors_hp_t hp;
    bftvmhors_keys_t keys;

    debug("Reading the config file...", DEBUG_INF);
    if (bftvmhors_new_hp(&hp, argv[1]) == BFTVMHORS_NEW_HP_FAILED)
        return 1;

    debug("Generating private and public keys...", DEBUG_INF);
    if (bftvmhors_keygen(&keys, &hp) == BFTVMHORS_KEYGEN_FAILED)
        return 1;

    /* Signer */
    debug("New signer is created", DEBUG_INF);
    bftvmhors_signer_t signer;
    bftvmhors_new_signer(&signer, &hp, &keys);
    bftvmhors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->l));

    /* Reading the message */
    u8 * message;
    u32 message_len;
    if ((message_len = read_file(&message, argv[2])) == FILE_OPEN_ERROR)
        return 1;

    bftvmhors_sign(&signature, &signer, message, message_len);
    debug("Signature is ready", DEBUG_INF);

    /* Verifier */
    debug("New verifier is created", DEBUG_INF);
    bftvmhors_verifier_t verifier;
    bftvmhors_new_verifier(&verifier, &keys.pk);

    if (bftvmhors_verify(&verifier, &hp, &signature, message, message_len) == BFTVMHORS_SIGNATURE_ACCEPTED)
        debug("Verification: Signature is valid", DEBUG_INF);
    else
        debug("Verification: Signature is (not) valid", DEBUG_INF);

    debug("Deleting hyper parameter and the keys", DEBUG_INF);
    bftvmhors_destroy_keys(&keys);
    bftvmhors_destroy_hp(&hp);

}

