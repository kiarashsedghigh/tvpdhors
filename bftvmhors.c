#include <bftvmhors/bf.h>
#include <bftvmhors/bftvmhors.h>
#include <bftvmhors/file.h>
#include <bftvmhors/prng.h>
#include <bftvmhors/hash.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/format.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>


u32 bftvmhors_new_hp(bftvmhors_hp_t * new_hp, const u8 * config_file){
    u8 line[100];

    read_file_line(line, 100, NULL);

    while(!read_file_line(line, 100, config_file)){
        char * token;
        char * delim = "=";

        /* get the first token */
        token = strtok(line, delim);
        /* walk through other tokens */
        while( token != NULL ) {
            if (!strcmp(token, "N")){
                if ((token = strtok(NULL, delim))){
                    new_hp->N = atoi(token); //TODO
                }else
                    return 1;

            }else if (!strcmp(token, "t")){
                if ((token = strtok(NULL, delim))){
                    new_hp->t = atoi(token); //TODO
                }else
                    return 1;

            }else if (!strcmp(token, "k")){
                if ((token = strtok(NULL, delim))){
                    new_hp->k = atoi(token); //TODO
                }else
                    return 1;

            }else if (!strcmp(token, "l")){
                if ((token = strtok(NULL, delim))){
                    new_hp->l = atoi(token); //TODO
                }else
                    return 1;

            }else if (!strcmp(token, "rejection_sampling")){
                if ((token = strtok(NULL, delim))){
                    if (strcmp(token,"true")==0)
                        new_hp->do_rejection_sampling=1;
                    else
                        new_hp->do_rejection_sampling=0;
                }else
                    return 1;
            }else if (!strcmp(token, "sk_seed_len")){
                if ((token = strtok(NULL, delim))){
                    new_hp->sk_seed_len = atoi(token); //TODO
                }else
                    return 1;

            }else if (!strcmp(token, "seed")) {
                if ((token = strtok(NULL, delim))) { // TODO
                    token = str_trim_char(token, '#');
                    new_hp->seed_file = malloc(strlen(token));
                    memcpy(new_hp->seed_file, token, strlen(token));
                } else
                    return 1;

            }else if (!strcmp(token, "m")){
                if ((token = strtok(NULL, delim))){
                    new_hp->sbf_hp.size = atoi(token); //TODO
                }else
                    return 1;

            }else if (!strcmp(token, "h")){
                if ((token = strtok(NULL, delim))){
                    new_hp->sbf_hp.num_hash_functions = atoi(token); //TODO
                }else
                    return 1;

            }else if (!strcmp(token, "h_family")){
                if ((token = strtok(NULL, delim))){
                    new_hp->sbf_hp.hash_family = token; //TODO
                }else
                    return 1;
            }else
                return 1;
            token = strtok(NULL, delim);
        }
    }
    return 0;
}

void bftvmhors_destroy_hp(bftvmhors_hp_t * bftvmhors_hp){
    free(bftvmhors_hp->seed_file);
}

u32 bftvmhors_keygen(bftvmhors_keys_t * keys, bftvmhors_hp_t * hp){

    /* Read the seed file */
    u32 seed_len = read_file(&keys->seed, hp->seed_file); //TODO check for the error

    /* Set the number of keys */
    keys->num_of_keys = hp->N;

    /* Generate the N private key seeds for N private keys */
    prng_chacha20(&keys->sk_seeds, keys->seed, seed_len, BITS_2_BYTES(hp->sk_seed_len) * hp->N); //TODO check for error

    /* Generate the PK */
    sbf_create(&keys->pk, &hp->sbf_hp);

    /* Add all the private keys to the SBF */
    for(u32 i=0; i<hp->N; i++){
        u8 * sk_seed = &keys->sk_seeds[i * BITS_2_BYTES(hp->sk_seed_len)];

        // Generate HORS private keys from the seed. t l-bit byte strings will be generated
        u8 * hors_sks;
        prng_chacha20(&hors_sks, sk_seed, BITS_2_BYTES(hp->sk_seed_len), BITS_2_BYTES(hp->l) * hp->t);

        // Inserting generated private keys into the SBF
        for (u32 j=0; j< hp->t; j++) {
            u8 * hors_sk = &hors_sks[j * BITS_2_BYTES(hp->l)];

            u8 element[100];//TODO
            u32 length = concat_buffers(element, hors_sk, BITS_2_BYTES(hp->l), &j, 4);
            length = concat_buffers(element, element, length, &i, 4);

            sbf_insert(&keys->pk, element, length);
        }
    }
    return 0; //TODO check error
}


bftvmhors_signer_t bftvmhors_new_signer(bftvmhors_hp_t * hp, bftvmhors_keys_t * keys){
        bftvmhors_signer_t signer;
        signer.state = 0;
        signer.keys = keys;
        signer.hp = hp;
        return signer;
}


static u32 rejection_sampling(u32 k, u32 t, u8 * message_hash, u8 * message, u64 message_len){
    u32 ctr = 0;
    u8 * buffer = malloc(message_len + sizeof(ctr));
    u8 * portion_number_memory = malloc(t);
    u32 bit_slice_len = log2(t);

    while(1) {
        memcpy(buffer, message, message_len);
        memcpy(buffer + message_len, &ctr, sizeof(ctr));
        u32 ctr_found=1;

        for(u32 i=0;i<t;i++)
            portion_number_memory[i]=0;

        hash_sha2_256(message_hash, buffer, message_len + sizeof(ctr));

        for(u32 i=0;i<k;i++){
            u32 portion_value = read_bits_as_4bytes(message_hash, i+1, bit_slice_len); //TODO
            if (portion_number_memory[portion_value]) {
                ctr_found=0;
                break;
            }else
                portion_number_memory[portion_value]=1;
        }
        if (ctr_found) {
            free(buffer);
            free(portion_number_memory);
            return ctr;
        }
        ctr++;
    }
}


static u32 is_rejected_sampling(u32 k, u32 t, u32 ctr, u8 * message_hash, u8 * message, u64 message_len){

    u8 * buffer = malloc(message_len + sizeof(ctr));
    u8 * portion_number_memory = malloc(t);
    u32 bit_slice_len = log2(t);

    memcpy(buffer, message, message_len);
    memcpy(buffer + message_len, &ctr, sizeof(ctr));
    u32 ctr_found=1;

    for(u32 i=0;i<t;i++)
        portion_number_memory[i]=0;

    hash_sha2_256(message_hash, buffer, message_len + sizeof(ctr));

    for(u32 i=0;i<k;i++){
        u32 portion_value = read_bits_as_4bytes(message_hash, i+1, bit_slice_len); //TODO

        if (portion_number_memory[portion_value])
            return 0;
        else
            portion_number_memory[portion_value]=1;
    }
    return 1;
}

u32 bftvmhors_sign(bftvmhors_signature_t * signature, bftvmhors_signer_t * signer, u8 * message, u64 message_len){

    /* Check for the signer state and the remaining keys */
    if (signer->state == signer->keys->num_of_keys)
        return 1;

    u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];


    /* Perform rejection sampling */

    if (signer->hp->do_rejection_sampling)
        signature->rejection_sampling_counter = rejection_sampling(signer->hp->k, signer->hp->t, message_hash, message, message_len);
    else
        /* Hashing the message */
        hash_sha2_256(message_hash, message, message_len);


    /* Generate the private keys of the current state */
    u8 * sk_seed = &signer->keys->sk_seeds[signer->state * BITS_2_BYTES(signer->hp->sk_seed_len)];
    u8 * current_state_keys;
    prng_chacha20(&current_state_keys, sk_seed, BITS_2_BYTES(signer->hp->sk_seed_len), BITS_2_BYTES(signer->hp->l) * signer->hp->t);


    /* Extract the portions from the private key and write to the signature */
    u32 bit_slice_len = log2(signer->hp->t);

    for(u32 i=0;i<signer->hp->k;i++){
        u32 portion_value = read_bits_as_4bytes(message_hash, i+1, bit_slice_len); //TODO
        memcpy(signature->signature + i* BITS_2_BYTES(signer->hp->l), current_state_keys + portion_value*BITS_2_BYTES(signer->hp->l), BITS_2_BYTES(signer->hp->l));
    }

    free(current_state_keys); //TODO check these
    signer->state++;
    return 0;
}

bftvmhors_verifier_t bftvmhors_new_verifier(sbf_t * pk){
    bftvmhors_verifier_t verifier;
    verifier.state = 0;
    verifier.pk = pk;
    return verifier;
}


u32 bftvmhors_verify(bftvmhors_verifier_t * verifier, bftvmhors_hp_t * hp, bftvmhors_signature_t * signature, u8 * message, u64 message_len){

    if (verifier->state == hp->N)
        return 1;

    u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];
    if (hp->do_rejection_sampling){
        if(!is_rejected_sampling(hp->k, hp->t, signature->rejection_sampling_counter, message_hash, message, message_len))
            return 1;
    }else
        /* Hashing the message */
        hash_sha2_256(message_hash, message, message_len);


    u32 bit_slice_len = log2(hp->t);

    for(u32 i=0;i<hp->k;i++) {
        u32 portion_value = read_bits_as_4bytes(message_hash, i+1, bit_slice_len); //TODO

        u8 element[100];//TODO
        u32 length = concat_buffers(element, signature->signature + i*BITS_2_BYTES(hp->l), BITS_2_BYTES(hp->l), &portion_value, 4);
        length = concat_buffers(element, element, length, &verifier->state, 4);

        if (!sbf_check(verifier->pk, element, length)){
            printf("Signature is not valid \n");
            verifier->state++;
            return 1;
        }
    }
    verifier->state++;
    return 0;
}



int main(){
    bftvmhors_hp_t bftvmhors_hp;
    bftvmhors_keys_t bftvmhors_keys;

    bftvmhors_new_hp(&bftvmhors_hp, "./config");
    bftvmhors_keygen(&bftvmhors_keys, &bftvmhors_hp);

    /* Signer */
    bftvmhors_signer_t signer = bftvmhors_new_signer(&bftvmhors_hp, &bftvmhors_keys);
    bftvmhors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->l));
    bftvmhors_sign(&signature, &signer , "aaa", 3);


    /* Verifier */
    bftvmhors_verifier_t verifier = bftvmhors_new_verifier(&bftvmhors_keys.pk);
    printf(">> %d\n", bftvmhors_verify(&verifier, &bftvmhors_hp, &signature, "thip is kiarash", 15));

    bftvmhors_destroy_hp(&bftvmhors_hp);
}
















