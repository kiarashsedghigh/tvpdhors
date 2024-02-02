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
    sbf->hash_functions = malloc(sizeof(u32(*)(u8 *, const u8 *, u64)) * sbf->size);
    for(int i=0;i<sbf->size;i++)
        sbf->hash_functions[i] = hash_sha2_256;

    return 0;
}

void sbf_destroy(const sbf_t * sbf){
    free(sbf->hash_functions);
    free(sbf->bv);
}



#define SBF_2_BYTE_IDX(idx) (idx/8)
#define SBF_2_BIT_IDX(idx) (idx%8)



void sbf_insert(const sbf_t * sbf, const u8 * input, u64 length){
//    u32 hash_sha2_256(u8 * hash_output, const u8 * input , u64 length);

    u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];

    for (u32 i=0; i<sbf->num_hash_functions ;i++){

        u8 concat_buffer_result[length+4]; //TODO
        length = concat_buffers(concat_buffer_result, input, length, (u8 *)&i, 4);

        u32 hash_size = sbf->hash_functions[i](hash_buffer, concat_buffer_result, length);

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
        sbf_current_byte |= 1 << SBF_2_BIT_IDX(target_idx);
        sbf->bv[SBF_2_BYTE_IDX(target_idx)] = sbf_current_byte;

    }

}


u32 sbf_check(const sbf_t * sbf, const u8 * input, u64 length){

    u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];

    for (u32 i=0; i<sbf->num_hash_functions ;i++){

        u8 concat_buffer_result[length+4];
        length = concat_buffers(concat_buffer_result, input, length, (u8 *)&i, 4);

        u32 hash_size = sbf->hash_functions[i](hash_buffer, concat_buffer_result, length);

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

        if ( !(sbf_current_byte & (1 << SBF_2_BIT_IDX(target_idx))) )
            return 0;
    }
    return 1;
}



//
//int main(){
//
////    sbf_hp_t  sbf_hp = sbf_hp_default;
////    sbf_t sbf = sbf_create(&sbf_hp);
////
////
////    sbf_insert(&sbf, "asd", 3);
////    printf("%d\n", sbf_check(&sbf,"vvvv",3));
////    sbf_destroy(&sbf);
//
//}




