#include <bftvmhors/bf.h>
#include <bftvmhors/file.h>
#include <bftvmhors/bftvmhors.h>
#include "./format.h" //TODO

#include <string.h>
#include <stdlib.h>
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

    /* Generate the N private key seeds for N messages */
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
        for (u32 j=0; j<hp->t; j++) {

            u8 * hors_sk = &hors_sks[j * BITS_2_BYTES(hp->l)];

            u8 element[100];//TODO
            u32 length = concat_buffers(element, hors_sk, BITS_2_BYTES(hp->l), &j, 4);
            sbf_insert(&keys->pk, element, length);
        }
    }
}

int main(){
    bftvmhors_hp_t bftvmhorsHp;
    bftvmhors_keys_t bftvmhorsKeys;

    bftvmhors_new_hp(&bftvmhorsHp, "./config");
    bftvmhors_keygen(&bftvmhorsKeys, &bftvmhorsHp);
//    bftvmhors_destroy_hp(&bftvmhorsHp);
}
















