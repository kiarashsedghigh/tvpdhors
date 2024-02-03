#include <bftvmhors/hors.h>
#include <bftvmhors/file.h>
#include <bftvmhors/format.h>
#include <bftvmhors/prng.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/hash.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


u32 hors_new_hp(hors_hp_t * new_hp, const u8 * config_file){
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

      }else
        return 1;
      token = strtok(NULL, delim);
    }
  }
  return 0;
}


u32 hors_keygen(hors_keys_t * keys, hors_hp_t * hp){

  /* Read the seed file */
  u8 * seed;

  u32 seed_len = read_file(&seed, hp->seed_file); //TODO check for the error

  /* Generate the t private keys */
  prng_chacha20(&keys->sk, seed, seed_len, BITS_2_BYTES(hp->l) * hp->t); //TODO check for error

  /* Generate the PK */
  keys->pk = malloc(BITS_2_BYTES(256)* hp->t); //TODO convert 256 to  a constant

  /* Compute OWF of privates as public key */
  for(u32 i=0; i<hp->t; i++){

    // Inserting generated private keys into the SBF
    for (u32 j=0; j< hp->t; j++) {
      u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];
      u32 hash_size = hash_sha2_256(message_hash, keys->sk + i*BITS_2_BYTES(hp->l), BITS_2_BYTES(hp->l));
      memcpy(keys->pk + i* BITS_2_BYTES(hp->l), message_hash, hash_size);
    }
  }

  return 0; //TODO check error
}



hors_signer_t hors_new_signer(hors_hp_t * hp, hors_keys_t * keys){
  hors_signer_t signer;
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


u32 hors_sign(hors_signature_t * signature, hors_signer_t * signer, u8 * message, u64 message_len){

  u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

  /* Perform rejection sampling */
  if (signer->hp->do_rejection_sampling)
    signature->rejection_sampling_counter = rejection_sampling(signer->hp->k, signer->hp->t, message_hash, message, message_len);
  else
    /* Hashing the message */
    hash_sha2_256(message_hash, message, message_len);

  /* Extract the portions from the private key and write to the signature */
  u32 bit_slice_len = log2(signer->hp->t);

  for(u32 i=0;i<signer->hp->k;i++){
    u32 portion_value = read_bits_as_4bytes(message_hash, i+1, bit_slice_len); //TODO
    memcpy(&signature->signature[i* BITS_2_BYTES(signer->hp->l)], &signer->keys->sk[portion_value*BITS_2_BYTES(signer->hp->l)], BITS_2_BYTES(signer->hp->l));
  }

  return 0;
}


hors_verifier_t bftvmhors_new_verifier(u8 * pk){
  hors_verifier_t verifier;
  verifier.pk = pk;
  return verifier;
}



u32 hors_verify(hors_verifier_t * verifier, hors_hp_t * hp, hors_signature_t * signature, u8 * message, u64 message_len){

  u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];
  if (hp->do_rejection_sampling){
    if(!is_rejected_sampling(hp->k, hp->t, signature->rejection_sampling_counter, message_hash, message, message_len))
      return 1;
  }else
    /* Hashing the message */
    hash_sha2_256(message_hash, message, message_len);


  u32 bit_slice_len = log2(hp->t);

  for(u32 i=0; i<hp->k; i++) {
    u32 portion_value = read_bits_as_4bytes(message_hash, i+1, bit_slice_len); //TODO

    u8 * pointed_signature_portion = &signature->signature[i * BITS_2_BYTES(hp->l)];
    u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];
    hash_sha2_256(message_hash, pointed_signature_portion, BITS_2_BYTES(hp->l));

    if (memcmp(message_hash, &verifier->pk[portion_value* BITS_2_BYTES(hp->l)],BITS_2_BYTES(hp->l))!=0){
      printf("Signature is not valid \n");
      verifier->state++;
      return 1;
    }

  }
  verifier->state++;
  return 0;
}


int main(){
  hors_hp_t  hors_hp;
  hors_keys_t hors_keys;
  hors_new_hp(&hors_hp, "./config");
  hors_keygen(&hors_keys, &hors_hp);

  hors_signer_t signer = hors_new_signer(&hors_hp, &hors_keys);
  hors_signature_t signature;
  signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->l));
  hors_sign(&signature, &signer , "qweqweqwe", 9);

  hors_verifier_t verifier = bftvmhors_new_verifier(hors_keys.pk);
  printf(">> %d\n", hors_verify(&verifier, &hors_hp, &signature, "aweqweqwe", 9));

}






