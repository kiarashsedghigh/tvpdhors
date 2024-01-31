#include "types.h"
#include "bf.h"

#include <stdio.h>
#include <stdlib.h>



//TODO check for family and other
sbf_hp_t sbf_new_hp(u32 size, u32 num_hash_functions, u8 * hash_family){
    sbf_hp_t sbf_hp;
    sbf_hp.size = size==0 ? sbf_hp_default.size:size;
    sbf_hp.num_hash_functions = num_hash_functions==0 ? sbf_hp_default.num_hash_functions: num_hash_functions;
    sbf_hp.hash_family = hash_family==NULL ? sbf_hp_default.hash_family:hash_family;
    return sbf_hp;
}


// TODO replace hash function
sbf_t sbf_creat(sbf_hp_t * sbf_hp){
    sbf_t sbf;
    sbf.size = sbf_hp->size;
    sbf.num_hash_functions = sbf_hp->num_hash_functions;
    sbf.bv = NULL;
    sbf.hash_functions = malloc(sizeof(void(*)(u32)) * sbf.size);
    for(int i=0;i<sbf.size;i++)
        sbf.hash_functions[i] = f;

    return sbf;
}

void sbf_destroy(sbf_t * sbf){
    free(sbf->hash_functions);
}


typedef void (*ff)(u32);
int main(){
    sbf_hp_t  sbf_hp = sbf_hp_default;
    sbf_t sbf = sbf_creat(&sbf_hp);


    for(int i=0;i<3;i++)
        sbf.hash_functions[i](i);

    sbf_destroy(&sbf);



}




