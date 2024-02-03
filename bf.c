#include <bftvmhors/bf.h>
#include <bftvmhors/hash.h>
#include <bftvmhors/format.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/bn.h>


//TODO check for family and other. Check for size to be *8
u32 sbf_new_hp(sbf_hp_t * sbf_hp, u32 size, u32 num_hash_functions, const u8 * hash_family){
    sbf_hp->size = size;
    sbf_hp->num_hash_functions = num_hash_functions;
    sbf_hp->hash_family = hash_family;
    return 0;
}


// TODO replace hash function, error return
u32 sbf_create(sbf_t * sbf ,const sbf_hp_t * sbf_hp){
    sbf->size = sbf_hp->size;
    sbf->num_hash_functions = sbf_hp->num_hash_functions;
    sbf->bv = malloc(sbf->size/8);
    /* Zero out the bit vector */
    for(u32 i=0; i< sbf->size/8; i++)
        sbf->bv[i]=0;

    sbf->hash_functions = malloc(sizeof(u32(*)(u8 *, const u8 *, u64)) * sbf->size);
    for(int i=0;i<sbf->size;i++)
        sbf->hash_functions[i] = fnv64_1; // hash_sha2_256 jenkins_oaat fnv64_0 fnv64_1 fnv64_1a

    return 0;
}

void sbf_destroy(const sbf_t * sbf){
    free(sbf->hash_functions);
    free(sbf->bv);
}

#define SBF_2_BYTE_IDX(idx) (idx/8)
#define SBF_2_BIT_IDX(idx) (idx%8)



void sbf_insert(const sbf_t * sbf, const u8 * input, u64 length){

    u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];

    u8 * concat_buffer_result = malloc(length+4);

    for (u32 i=0; i<sbf->num_hash_functions ;i++){

        u32 new_length = concat_buffers(concat_buffer_result, input, length, (u8 *)&i, 4);

        u32 hash_size = sbf->hash_functions[i](hash_buffer, concat_buffer_result, new_length);

        /* Convert the hash value to BigNum for further evaluations.
         *
         * We compute:
         *              rem = hash % SBF_SIZE
         * */
        BIGNUM * hash_bn = BN_new();
        BIGNUM * sbf_size_bn = BN_new();
        BIGNUM * rem = BN_new();
        BN_bin2bn(hash_buffer, hash_size, hash_bn);

        u8 len[100]; //TODO
        sprintf(len, "%d", sbf->size);
        BN_dec2bn(&sbf_size_bn,len);

        BN_mod(rem, hash_bn, sbf_size_bn, BN_CTX_new());

        u32 target_idx = atoi(BN_bn2dec(rem)); //TODO

        u8 sbf_current_byte = sbf->bv[SBF_2_BYTE_IDX(target_idx)];
        sbf_current_byte |= 1 << (8-SBF_2_BIT_IDX(target_idx)-1);
        sbf->bv[SBF_2_BYTE_IDX(target_idx)] = sbf_current_byte;

    }
    free(concat_buffer_result);

}


u32 sbf_check(const sbf_t * sbf, const u8 * input, u64 input_length){

    u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];
    u8 * concat_buffer_result = malloc(input_length+4);

    for (u32 i=0; i<sbf->num_hash_functions ;i++){

        u8 new_length = concat_buffers(concat_buffer_result, input, input_length, (u8 *)&i, 4);
        u32 hash_size = sbf->hash_functions[i](hash_buffer, concat_buffer_result, new_length);

        BIGNUM * hash_bn = BN_new();
        BIGNUM * sbf_size_bn = BN_new();
        BIGNUM * rem = BN_new();
        BN_bin2bn(hash_buffer, hash_size, hash_bn);

        u8 len[100];
        sprintf(len, "%d", sbf->size);
        BN_dec2bn(&sbf_size_bn,len);

        BN_mod(rem, hash_bn, sbf_size_bn, BN_CTX_new());

        u32 target_idx = atoi(BN_bn2dec(rem));
        u8 sbf_current_byte = sbf->bv[SBF_2_BYTE_IDX(target_idx)];

        if ( !(sbf_current_byte & (1 << ( 8-SBF_2_BIT_IDX(target_idx)-1) )) ){
            free(concat_buffer_result);
            return 0;
        }
    }
    free(concat_buffer_result);
    return 1;
}