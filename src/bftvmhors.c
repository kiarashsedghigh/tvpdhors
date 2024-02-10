#include <bftvmhors/bf.h>
#include <bftvmhors/bftvmhors.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/file.h>
#include <bftvmhors/format.h>
#include <bftvmhors/hash.h>
#include <bftvmhors/prng.h>
#include <bftvmhors/tv_params.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Time information variables/functions for BFTVMHORS */
#ifdef TIMEKEEPING
struct timeval start_time, end_time;

static double bftvmhors_keygen_time = 0;
static double bftvmhors_sign_time = 0;
static double bftvmhors_verify_time = 0;

double bftvmhors_get_keygen_time(){
    return bftvmhors_keygen_time;
}
double bftvmhors_get_sign_time(){
    return bftvmhors_sign_time;
}
double bftvmhors_get_verify_time(){
    return bftvmhors_verify_time;
}
#endif

#define CONFIG_FILE_MAX_LENGTH 300


/// Struct for the parameters needed to be passed to the running thread of the keygen
typedef struct bftvmhors_keygen_thread_argument{
    u8*current_state_sks;       // Private keys of the current state
    u32 private_key_start;      // Index of the first key
    u32 private_key_end;        // Index of the last key
    bftvmhors_keys_t* keys;     // Keys
    bftvmhors_hp_t* hp;         // Hyper parameters
    u32 state;                  // State of the signer
}bftvmhors_keygen_thread_argument_t;


/// Running thread of the keygen
/// \param args Struct for the parameters needed to be passed to the running thread of the keygen
void bftvmhors_keygen_thread(bftvmhors_keygen_thread_argument_t * args){

    for(u32 j=args->private_key_start; j<args->private_key_end; j++) {
        u8 *hors_sk = &args->current_state_sks[j * BITS_2_BYTES(args->hp->l)];


#ifdef TVHASHOPTIMIZED

        /* Add state and index to the private key */ //TODO little endian/big endin with int *
          hors_sk[0] += j;
          hors_sk[0] += args->state;

    #ifdef OHBF
          printf("OH");
          ohbf_insert(&args->keys->pk, hors_sk, BITS_2_BYTES(args->hp->l));
    #else
          sbf_insert(&args->keys->pk, hors_sk, BITS_2_BYTES(args->hp->l));
    #endif

#else
        u8 * concat_buffer; u32 concat_buffer_length;
        /* Concatenating the HORS private key with index and state sk||i||state */
        concat_buffer = malloc(BITS_2_BYTES(args->hp->l) + 2 * sizeof(u32));
        concat_buffer_length = concat_buffers(concat_buffer, hors_sk, BITS_2_BYTES(args->hp->l), &j, sizeof(u32));
        concat_buffer_length = concat_buffers(concat_buffer, concat_buffer, concat_buffer_length, &args->state, sizeof(u32));
#ifdef OHBF
        ohbf_insert(&args->keys->pk, concat_buffer, concat_buffer_length);
#else
        sbf_insert(&args->keys->pk, concat_buffer, concat_buffer_length);
#endif
        free(concat_buffer);

#endif


    }
    pthread_exit(NULL);
}



u32 bftvmhors_keygen(bftvmhors_keys_t* keys, bftvmhors_hp_t* hp) {
    /* Read the seed file */
  u32 seed_len = read_file(&keys->seed, hp->seed_file);

  /* Set the number of keys */
  keys->num_of_keys = hp->N;

  /* Generate the N seeds for N private keys */
  prng_chacha20(&keys->sk_seeds, keys->seed, seed_len,
                BITS_2_BYTES(hp->sk_seed_len) * hp->N);

  /* Generate the PK */
#ifdef OHBF
    ohbf_create(&keys->pk, &hp->ohbf_hp);
#else
  sbf_create(&keys->pk, &hp->sbf_hp);
#endif

  /* Add all the private keys to the SBF */
  for (u32 i = 0; i < hp->N; i++) {
    u8*current_state_sk_seed = &keys->sk_seeds[i * BITS_2_BYTES(hp->sk_seed_len)];

    // Generate HORS private keys from the seed. t l-bit strings will be generated as private keys
    u8*current_state_sks;
    prng_chacha20(&current_state_sks, current_state_sk_seed, BITS_2_BYTES(hp->sk_seed_len), BITS_2_BYTES(hp->l) * hp->t);

#ifdef TIMEKEEPING
      gettimeofday(&start_time, NULL);
#endif
    /* Inserting generated private keys into the SBF */
#ifdef MULTITHREAD
    u32 number_of_threads = hp->t/BFTVMHORS_KEYGEN_THREAD_CAPACITY;
    pthread_t * threads = malloc(sizeof(pthread_t) * number_of_threads);

    bftvmhors_keygen_thread_argument_t thread_arg_template = {
            current_state_sks, 0, 0, keys, hp, i
    };

    struct bftvmhors_keygen_thread_argument * args = malloc(sizeof(bftvmhors_keygen_thread_argument_t) * number_of_threads);
    for(int i=0;i<number_of_threads;i++){
        thread_arg_template.private_key_start = i*BFTVMHORS_KEYGEN_THREAD_CAPACITY;
        thread_arg_template.private_key_end = (i+1)*BFTVMHORS_KEYGEN_THREAD_CAPACITY-1;
        args[i] = thread_arg_template;
    }
#ifdef TIMEKEEPING
      gettimeofday(&start_time, NULL);
#endif
    for(int i=0;i<number_of_threads;i++)
        pthread_create(&threads[i], NULL, bftvmhors_keygen_thread, (void *)&args[i]);

    for (int i = 0; i < number_of_threads; ++i)
        pthread_join(threads[i], NULL);




















#else

    for (u32 j = 0; j < hp->t; j++) {
      u8* hors_sk = &current_state_sks[j * BITS_2_BYTES(hp->l)];

#ifdef TVHASHOPTIMIZED
    /* Add state and index to the private key */ //TODO little endian/big endin with int *
    hors_sk[0] += i;
    hors_sk[0] += j;

    #ifdef OHBF
          ohbf_insert(&keys->pk, hors_sk, BITS_2_BYTES(hp->l));
    #else
          sbf_insert(&keys->pk, hors_sk, BITS_2_BYTES(hp->l));
    #endif

#else
      u8 * concat_buffer; u32 concat_buffer_length;
      /* Concatenating the HORS private key with index and state sk||i||state */
      concat_buffer = malloc(BITS_2_BYTES(hp->l) + 2 * sizeof(u32));
      concat_buffer_length = concat_buffers(concat_buffer, hors_sk, BITS_2_BYTES(hp->l), &j, sizeof(u32));
      concat_buffer_length = concat_buffers(concat_buffer, concat_buffer, concat_buffer_length, &i, sizeof(u32));
    #ifdef OHBF
            ohbf_insert(&keys->pk, concat_buffer, concat_buffer_length);
    #else
            sbf_insert(&keys->pk, concat_buffer, concat_buffer_length);
    #endif
            free(concat_buffer);

#endif


    }
#endif

#ifdef TIMEKEEPING
   gettimeofday(&end_time, NULL);
   bftvmhors_keygen_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif
    free(current_state_sks);
  }
  return BFTVMHORS_KEYGEN_SUCCESS;
}


/// Performing the rejection sampling on the input message to achieve higher security in HORS-based signatures. (Assumes rejection sampling is always successful)
/// \param k HORS k parameter
/// \param t HORS t parameter
/// \param ctr Pointer to the rejection sampling 4-byte variable where the found counter will be written into it
/// \param message_hash Pointer to a buffer for writing the resulting hash into for not doing it again when signing
/// \param message  Pointer to the message to check signature on
/// \param message_len  Length of the input message
/// \return BFTVMHORS_REJECTION_SAMPLING_SUCCESS, BFTVMHORS_REJECTION_SAMPLING_FAILED
static u32 rejection_sampling(u32 k, u32 t, u32 * ctr, u8* message_hash, u8* message, u64 message_len) {

  /* A message_counter_buffer containing the input message and the incremental counter */
  u8*message_counter_buffer = malloc(message_len + sizeof(u32));

  /* Creating a dictionary to see if a portion has already been generated from the hash of the message */
  u8*portion_number_dict = malloc(t);

  /* HORS log(t), defining size of the bit slices */
  u32 bit_slice_len = log2(t);

  while (1) {
    memcpy(message_counter_buffer, message, message_len);
    memcpy(message_counter_buffer + message_len, ctr, sizeof(u32));
    u32 ctr_found = 1;

    /* Clear the dictionary */
    for (u32 i = 0; i < t; i++)
      portion_number_dict[i] = 0;

    ltc_hash_sha2_256(message_hash, message_counter_buffer, message_len + sizeof(u32));

    for (u32 i = 0; i < k; i++) {
      u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);
      if (portion_number_dict[portion_value]) {
        ctr_found = 0;
        break;
      } else
        portion_number_dict[portion_value] = 1;
    }
    if (ctr_found) {
      free(message_counter_buffer);
      free(portion_number_dict);
      return BFTVMHORS_REJECTION_SAMPLING_SUCCESS;
    }
    *ctr++;
    /* If rejection sampling goes infinite times, we will reach 0 again in a 4-byte variable */
    if (!*ctr)
      return BFTVMHORS_REJECTION_SAMPLING_FAILED;
  }
}


/// Checks if the rejection sampling has been done by checking if the passed counter is a valid counter
/// \param k HORS k parameter
/// \param t HORS t parameter
/// \param ctr 4-byte rejection sampling counter
/// \param message_hash Pointer to a buffer for writing the resulting hash into for not doing it again when signing
/// \param message  Pointer to the message to check signature on
/// \param message_len  Length of the input message
/// \return BFTVMHORS_REJECTION_SAMPLING_DONE, BFTVMHORS_REJECTION_SAMPLING_NOT_DONE
static u32 rejection_sampling_status(u32 k, u32 t, u32 ctr, u8* message_hash, u8* message,
                                u64 message_len) {

  /* A message_counter_buffer containing the input message and the incremental counter */
  u8*message_counter_buffer = malloc(message_len + sizeof(u32));

  /* Creating a dictionary to see if a portion has already been generated from the hash of the message */
  u8*portion_number_dict = malloc(t);

  /* HORS log(t), defining size of the bit slices */
  u32 bit_slice_len = log2(t);

  memcpy(message_counter_buffer, message, message_len);
  memcpy(message_counter_buffer + message_len, &ctr, sizeof(u32));
  u32 ctr_found = 1;

  /* Clear the dictionary */
  for (u32 i = 0; i < t; i++) portion_number_dict[i] = 0;

  ltc_hash_sha2_256(message_hash, message_counter_buffer, message_len + sizeof(u32));
  for (u32 i = 0; i < k; i++) {
    u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);
    if (portion_number_dict[portion_value])
      return BFTVMHORS_REJECTION_SAMPLING_NOT_DONE;
    else
      portion_number_dict[portion_value] = 1;
  }
  return BFTVMHORS_REJECTION_SAMPLING_DONE;
}



bftvmhors_signer_t bftvmhors_new_signer(bftvmhors_hp_t* hp, bftvmhors_keys_t* keys) {
  bftvmhors_signer_t signer;
  signer.state = 0;
  signer.keys = keys;
  signer.hp = hp;
  return signer;
}



u32 bftvmhors_sign(bftvmhors_signature_t* signature, bftvmhors_signer_t* signer, u8* message,
                   u64 message_len) {
  /* Check for the signer state and the remaining keys */
  if (signer->state == signer->keys->num_of_keys) return BFTVMHORS_SIGNING_FAILED;

  u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

#ifdef TIMEKEEPING
    gettimeofday(&start_time, NULL);
#endif
  /* Perform rejection sampling */
  if (signer->hp->do_rejection_sampling) {
    if (rejection_sampling(signer->hp->k, signer->hp->t,
                           &signature->rejection_sampling_counter, message_hash,
                           message,
                           message_len) == BFTVMHORS_REJECTION_SAMPLING_FAILED)
      BFTVMHORS_SIGNING_FAILED;
  }else
    /* Hashing the message */
    ltc_hash_sha2_256(message_hash, message, message_len);

  /* Generate the private keys of the current state using the seed of the current state */
  u8* current_state_sk_seed =
      &signer->keys->sk_seeds[signer->state * BITS_2_BYTES(signer->hp->sk_seed_len)];
  u8* current_state_sk_keys;
  prng_chacha20(&current_state_sk_keys, current_state_sk_seed,
                BITS_2_BYTES(signer->hp->sk_seed_len), BITS_2_BYTES(signer->hp->l) * signer->hp->t);

  /* HORS log(t), defining size of the bit slices */
  u32 bit_slice_len = log2(signer->hp->t);

  /* Extract the portions from the private key and write to the signature */
  for (u32 i = 0; i < signer->hp->k; i++) {
    u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);

    memcpy(signature->signature + i * BITS_2_BYTES(signer->hp->l),
           current_state_sk_keys + portion_value * BITS_2_BYTES(signer->hp->l),
           BITS_2_BYTES(signer->hp->l));
  }
#ifdef TIMEKEEPING
    gettimeofday(&end_time, NULL);
   bftvmhors_sign_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif
  free(current_state_sk_keys);
  signer->state++;

  return BFTVMHORS_SIGNING_SUCCESS;
}


bftvmhors_verifier_t bftvmhors_new_verifier(sbf_t* pk) {
  bftvmhors_verifier_t verifier;
  verifier.state = 0;
  verifier.pk = pk;
  return verifier;
}


u32 bftvmhors_verify(bftvmhors_verifier_t* verifier, bftvmhors_hp_t* hp,
                     bftvmhors_signature_t* signature, u8* message, u64 message_len) {
  /* Verifier is no longer verifying any message */
  if (verifier->state == hp->N) return BFTVMHORS_SIGNATURE_REJECTED;

  u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

#ifdef TIMEKEEPING
    gettimeofday(&start_time, NULL);
#endif

  /* Check if the received signature has done the rejection sampling */
  if (hp->do_rejection_sampling) {
    if (rejection_sampling_status(
            hp->k, hp->t, signature->rejection_sampling_counter, message_hash,
            message, message_len) == BFTVMHORS_REJECTION_SAMPLING_NOT_DONE)
      return BFTVMHORS_SIGNATURE_REJECTED;
  } else
    /* Hashing the message */
    ltc_hash_sha2_256(message_hash, message, message_len);

  /* HORS log(t), defining size of the bit slices */
  u32 bit_slice_len = log2(hp->t);

  /* Allocate a buffer for concatenating signature, portion index, and the verifier state */
  u8* concat_buffer = malloc(hp->k * BITS_2_BYTES(hp->l) + 2 * sizeof(u32));

  for (u32 i = 0; i < hp->k; i++) {
    u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);

    /* Concat signature with portion index */
    u32 concat_buffer_length =
        concat_buffers(concat_buffer, signature->signature + i * BITS_2_BYTES(hp->l),
                       BITS_2_BYTES(hp->l), &portion_value, sizeof(u32));

    /* Concat signature/index with state */
    concat_buffer_length = concat_buffers(concat_buffer, concat_buffer, concat_buffer_length,
                                          &verifier->state, sizeof(u32));

#ifdef OHBF

      /* Check if the value exists in the BF */
        if (ohbf_check(verifier->pk, concat_buffer, concat_buffer_length) == SBF_ELEMENT_ABSENTS) {
          free(concat_buffer);
          verifier->state = 0;
    #ifdef TIMEKEEPING
        /* We put the timing here as to get timing until the point that the signature is valid */
        gettimeofday(&end_time, NULL);
        bftvmhors_verify_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
    #endif
          return BFTVMHORS_SIGNATURE_REJECTED;
        }

#else
        /* Check if the value exists in the BF */
        if (sbf_check(verifier->pk, concat_buffer, concat_buffer_length) == SBF_ELEMENT_ABSENTS) {
          free(concat_buffer);
          verifier->state = 0;
    #ifdef TIMEKEEPING
        /* We put the timing here as to get timing until the point that the signature is valid */
        gettimeofday(&end_time, NULL);
        bftvmhors_verify_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
    #endif
          return BFTVMHORS_SIGNATURE_REJECTED;
        }
#endif

  }
#ifdef TIMEKEEPING
   gettimeofday(&end_time, NULL);
   bftvmhors_verify_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif
  free(concat_buffer);
  verifier->state++;
  return BFTVMHORS_SIGNATURE_ACCEPTED;
}


u32 bftvmhors_new_hp(bftvmhors_hp_t* new_hp, const u8* config_file) {
  u8 line_buffer[CONFIG_FILE_MAX_LENGTH];

  /* Parameters of the underlying BF */
  u32 bf_size;
  u8 * bf_hash_family;

#ifdef OHBF
  /* Parameters of the underlying OHBF */
  u32 ohbf_num_mod_operations;
#else
    /* Parameters of the underlying SBF */
    u32 sbf_num_hash_functions;
#endif

    read_file_line(line_buffer, CONFIG_FILE_MAX_LENGTH, NULL);

  while (!read_file_line(line_buffer, CONFIG_FILE_MAX_LENGTH, config_file)) {
    u8* trimmed_line = str_trim(line_buffer);

    /* Ignore empty lines */
    if (!strlen(trimmed_line)) continue;

    char* token;
    char* delim = "=";

    /* Get the first token */
    token = strtok(trimmed_line, delim);
    token = str_trim(token);

    /* walk through other tokens */
    while (token != NULL) {
      /* If the line is a comment, ignore it */
      if (token[0] == '#') break;

      if (!strcmp(token, "N")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->N = strtol(token, NULL, 10);
        } else
          return BFTVMHORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "t")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->t = strtol(token, NULL, 10);
        } else
          return BFTVMHORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "k")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->k = strtol(token, NULL, 10);
        } else
          return BFTVMHORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "l")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->l = strtol(token, NULL, 10);
        } else
          return BFTVMHORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "lpk")) {
          if ((token = strtok(NULL, delim))) {
              token = str_trim_char(token, '#');
              new_hp->lpk = strtol(token, NULL, 10);
          } else
              return BFTVMHORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "rejection_sampling")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          if (strcmp(token, "true") == 0)
            new_hp->do_rejection_sampling = 1;
          else
            new_hp->do_rejection_sampling = 0;
        } else
          return BFTVMHORS_NEW_HP_FAILED;
      } else if (!strcmp(token, "sk_seed_len")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->sk_seed_len = strtol(token, NULL, 10);
        } else
          return BFTVMHORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "seed")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          new_hp->seed_file = malloc(strlen(token));
          memcpy(new_hp->seed_file, token, strlen(token));
        } else
          return BFTVMHORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "m")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          bf_size = strtol(token, NULL, 10);
        } else
          return BFTVMHORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "h")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
#ifdef OHBF
   ohbf_num_mod_operations = strtol(token, NULL, 10);
#else
   sbf_num_hash_functions = strtol(token, NULL, 10);
#endif
        } else
          return BFTVMHORS_NEW_HP_FAILED;

      } else if (!strcmp(token, "h_family")) {
        if ((token = strtok(NULL, delim))) {
          token = str_trim_char(token, '#');
          bf_hash_family = malloc(strlen(token));
          memcpy(bf_hash_family, token, strlen(token));
        } else
          return BFTVMHORS_NEW_HP_FAILED;
      }
      token = strtok(NULL, delim);
    }
  }


#ifdef TVHASHOPTIMIZED
  new_hp->l = TVOPTIMIZED_L;
  new_hp->k = TVOPTIMIZED_K;
  new_hp->t = TVOPTIMIZED_T;
  new_hp->lpk = TVOPTIMIZED_LPK;
#endif


  /* Create the hyper parameter structure of the underlying BF */
#ifdef OHBF
    ohbf_new_hp(&new_hp->ohbf_hp, bf_size, ohbf_num_mod_operations, bf_hash_family);
#else
  new_hp->sbf_hp = sbf_new_hp(bf_size, sbf_num_hash_functions, bf_hash_family);
#endif
  return BFTVMHORS_NEW_HP_SUCCESS;
}


void bftvmhors_destroy_hp(bftvmhors_hp_t* bftvmhors_hp) { free(bftvmhors_hp->seed_file); }

