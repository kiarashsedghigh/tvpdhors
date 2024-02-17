#include <bftvmhors/hash.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/file.h>
#include <bftvmhors/format.h>
#include <bftvmhors/hors.h>
#include <bftvmhors/prng.h>
#include <bftvmhors/tv_params.h>
#include <bftvmhors/debug.h>
#include <sys/time.h>
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_FILE_MAX_LENGTH 300

/* Time information variables/functions for HORS */
#ifdef TIMEKEEPING
struct timeval start_time, end_time;

static double hors_keygen_time = 0;
static double hors_sign_time = 0;
static double hors_verify_time = 0;

double hors_get_keygen_time() { return hors_keygen_time; }
double hors_get_sign_time() { return hors_sign_time; }
double hors_get_verify_time() { return hors_verify_time; }
#endif

/// Struct for the parameters needed to be passed to the running thread of the keygen
typedef struct hors_keygen_thread_argument {
    hors_keys_t* keys;      // Keys
    hors_hp_t* hp;          // Hyper parameters
    u32 private_key_start;  // Index of the first private key
    u32 private_key_end;    // Index of the last private key
} hors_keygen_thread_argument_t;

/// Running thread of the keygen
/// \param args Struct for the parameters needed to be passed to the running thread of the keygen
static void hors_keygen_thread(hors_keygen_thread_argument_t* args) {
    /* Compute OWF of private keys as public key */
    for (u32 i = args->private_key_start; i <= args->private_key_end; i++) {
        u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

#ifdef TVHASHOPTIMIZED
        TVOPTIMIZED_HORS_HASH_FUNCTION(
        message_hash, args->keys->sk + i * BITS_2_BYTES(args->hp->l),
        BITS_2_BYTES(args->hp->l));
#else
        ltc_hash_sha2_256(message_hash,
                          args->keys->sk + i * BITS_2_BYTES(args->hp->l),
                          BITS_2_BYTES(args->hp->l));
#endif
        memcpy(args->keys->pk + i * BITS_2_BYTES(args->hp->lpk),
               message_hash,
               BITS_2_BYTES(args->hp->lpk));
    }
    pthread_exit(NULL);
}


u32 hors_keygen(hors_keys_t* keys, hors_hp_t* hp) {
    /* Read the seed file */
    u8* seed;

    u32 seed_len;

    if ((seed_len = read_file(&seed, hp->seed_file)) == FILE_OPEN_ERROR) {
        debug("Seed file does not exist", DEBUG_ERR);
        return HORS_KEYGEN_FAILED;
    }

    /* Generate the t private keys */
    prng_chacha20(&keys->sk, seed, seed_len, BITS_2_BYTES(hp->l) * hp->t);

    /* Generate the PK */
    keys->pk = malloc(BITS_2_BYTES(hp->lpk) * hp->t);

#ifdef MULTITHREAD

    /* Compute the number of threads and allocate array of threads */
    u32 number_of_threads = hp->t / HORS_KEYGEN_THREAD_CAPACITY;
    pthread_t* threads = malloc(sizeof(pthread_t) * number_of_threads);

    /* A template for the thread argument as the start and end index of the key is
    * different for each thread. */
    hors_keygen_thread_argument_t keygen_thread_arg_template = {keys, hp, 0, 0};

    /* Allocate thread argument structs for the threads */
    struct hors_keygen_thread_argument* args =
      malloc(sizeof(hors_keygen_thread_argument_t) * number_of_threads);

    for (u32 i = 0; i < number_of_threads; i++) {
    keygen_thread_arg_template.private_key_start =
        i * HORS_KEYGEN_THREAD_CAPACITY;
    keygen_thread_arg_template.private_key_end =
        (i + 1) * HORS_KEYGEN_THREAD_CAPACITY - 1;
    args[i] = keygen_thread_arg_template;
    }

    #ifdef TIMEKEEPING
    gettimeofday(&start_time, NULL);
    #endif
    for (int i = 0; i < number_of_threads; i++)
    pthread_create(&threads[i], NULL, hors_keygen_thread, (void*)&args[i]);

    for (int i = 0; i < number_of_threads; ++i) pthread_join(threads[i], NULL);
    free(threads);
    free(args);
#else

#ifdef TIMEKEEPING
    gettimeofday(&start_time, NULL);
#endif
    /* Compute OWF of privates as public key */
    for (u32 i = 0; i < hp->t; i++) {
        u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];
#ifdef TVHASHOPTIMIZED
        TVOPTIMIZED_HORS_HASH_FUNCTION(
        message_hash, keys->sk + i * BITS_2_BYTES(hp->l), BITS_2_BYTES(hp->l));
#else
        ltc_hash_sha2_256(message_hash, keys->sk + i * BITS_2_BYTES(hp->l),
                          BITS_2_BYTES(hp->l));
#endif
        memcpy(keys->pk + i * BITS_2_BYTES(hp->lpk), message_hash,
               BITS_2_BYTES(hp->lpk));
    }
#endif

#ifdef TIMEKEEPING
    gettimeofday(&end_time, NULL);
  hors_keygen_time = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif

    return HORS_KEYGEN_SUCCESS;
}


void hors_destroy_keys(hors_keys_t* keys){
    free(keys->sk);
    free(keys->pk);
}

/// Performing the rejection sampling on the input message to achieve higher
/// security in HORS-based signatures. (Assumes rejection sampling is always
/// successful) \param k HORS k parameter \param t HORS t parameter \param ctr
/// Pointer to the rejection sampling 4-byte variable where the found counter
/// will be written into it \param message_hash Pointer to a buffer for writing
/// the resulting hash into for not doing it again when signing \param message
/// Pointer to the message to check signature on \param message_len  Length of
/// the input message \return HORS_REJECTION_SAMPLING_SUCCESS,
/// HORS_REJECTION_SAMPLING_FAILED
static u32 rejection_sampling(u32 k, u32 t, u32* ctr, u8* message_hash,
                              u8* message, u64 message_len) {
    /* A message_counter_buffer containing the input message and the incremental
     * counter */
    u8* message_counter_buffer = malloc(message_len + sizeof(u32));

    /* Creating a dictionary to see if a portion has already been generated from
     * the hash of the message */
    u8* portion_number_dict = malloc(t);

    /* HORS log(t), defining size of the bit slices */
    u32 bit_slice_len = log2(t);

    while (1) {
        memcpy(message_counter_buffer, message, message_len);
        memcpy(message_counter_buffer + message_len, ctr, sizeof(u32));
        u32 ctr_found = 1;

        /* Clear the dictionary */
        for (u32 i = 0; i < t; i++) portion_number_dict[i] = 0;

        ltc_hash_sha2_256(message_hash, message_counter_buffer,
                          message_len + sizeof(u32));

        for (u32 i = 0; i < k; i++) {
            u32 portion_value =
                    read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);
            if (portion_number_dict[portion_value]) {
                ctr_found = 0;
                break;
            } else
                portion_number_dict[portion_value] = 1;
        }
        if (ctr_found) {
            free(message_counter_buffer);
            free(portion_number_dict);
            return HORS_REJECTION_SAMPLING_SUCCESS;
        }
        *ctr++;
        /* If rejection sampling goes infinite times, we will reach 0 again in a
         * 4-byte variable */
        if (!*ctr) return HORS_REJECTION_SAMPLING_FAILED;
    }
}

/// Checks if the rejection sampling has been done by checking if the passed
/// counter is a valid counter \param k HORS k parameter \param t HORS t
/// parameter \param ctr 4-byte rejection sampling counter \param message_hash
/// Pointer to a buffer for writing the resulting hash into for not doing it
/// again when signing \param message  Pointer to the message to check signature
/// on \param message_len  Length of the input message \return
/// HORS_REJECTION_SAMPLING_DONE, HORS_REJECTION_SAMPLING_NOT_DONE
static u32 rejection_sampling_status(u32 k, u32 t, u32 ctr, u8* message_hash,
                                     u8* message, u64 message_len) {
    /* A message_counter_buffer containing the input message and the incremental
     * counter */
    u8* message_counter_buffer = malloc(message_len + sizeof(u32));

    /* Creating a dictionary to see if a portion has already been generated from
     * the hash of the message */
    u8* portion_number_dict = malloc(t);

    /* HORS log(t), defining size of the bit slices */
    u32 bit_slice_len = log2(t);

    memcpy(message_counter_buffer, message, message_len);
    memcpy(message_counter_buffer + message_len, &ctr, sizeof(u32));
    u32 ctr_found = 1;

    /* Clear the dictionary */
    for (u32 i = 0; i < t; i++) portion_number_dict[i] = 0;

    ltc_hash_sha2_256(message_hash, message_counter_buffer,
                      message_len + sizeof(u32));
    for (u32 i = 0; i < k; i++) {
        u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);
        if (portion_number_dict[portion_value])
            return HORS_REJECTION_SAMPLING_NOT_DONE;
        else
            portion_number_dict[portion_value] = 1;
    }
    return HORS_REJECTION_SAMPLING_DONE;
}

/// Passing the HORS hyper parameters and the keys it creates a HORS signer
/// \param hp HORS hyper parameter
/// \param keys HORS keys
/// \return HORS signer
u32 hors_new_signer(hors_signer_t* signer, hors_hp_t* hp, hors_keys_t* keys) {
    /* State has not been set as this is a one-time HORS */
    signer->keys = keys;
    signer->hp = hp;
    return HORS_NEW_SIGNER_SUCCESS;
}


u32 hors_sign(hors_signature_t* signature, hors_signer_t* signer, u8* message, u64 message_len) {
    u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

#ifdef TIMEKEEPING
        gettimeofday(&start_time, NULL);
#endif
    /* Perform rejection sampling */
    if (signer->hp->do_rejection_sampling) {
        if (rejection_sampling(signer->hp->k, signer->hp->t,
                               &signature->rejection_sampling_counter, message_hash,
                               message,
                               message_len) == HORS_REJECTION_SAMPLING_FAILED)
            return HORS_SIGNING_FAILED;
    } else
        /* Hashing the message without rejection sampling */
        ltc_hash_sha2_256(message_hash, message, message_len);

    /* HORS log(t), defining size of the bit slices */
    u32 bit_slice_len = log2(signer->hp->t);

    /* Extract the portions from the private key and write to the signature */
    for (u32 i = 0; i < signer->hp->k; i++) {
        u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);
        memcpy(&signature->signature[i * BITS_2_BYTES(signer->hp->l)],
               &signer->keys->sk[portion_value * BITS_2_BYTES(signer->hp->l)],
               BITS_2_BYTES(signer->hp->l));
    }
#ifdef TIMEKEEPING
    gettimeofday(&end_time, NULL);
    hors_sign_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif
    return HORS_SIGNING_SUCCESS;
}


u32 hors_new_verifier(hors_verifier_t* verifier, u8* pk) {
    /* State has not been set as this is a one-time HORS */
    verifier->pk = pk;
    return HORS_NEW_VERIFIER_SUCCESS;
}



u32 hors_verify(hors_verifier_t* verifier, hors_hp_t* hp, hors_signature_t* signature, u8* message, u64 message_len) {
    u8 message_hash[HASH_MAX_LENGTH_THRESHOLD];

#ifdef TIMEKEEPING
    gettimeofday(&start_time, NULL);
#endif
    /* Perform rejection sampling */
    if (hp->do_rejection_sampling) {
        if (rejection_sampling_status(hp->k, hp->t,
                                      signature->rejection_sampling_counter, message_hash,
                                      message, message_len) == HORS_REJECTION_SAMPLING_NOT_DONE)
            return HORS_SIGNATURE_REJECTED;
    } else
        /* Hashing the message without rejection sampling */
        ltc_hash_sha2_256(message_hash, message, message_len);

    /* HORS log(t), defining size of the bit slices */
    u32 bit_slice_len = log2(hp->t);

    for (u32 i = 0; i < hp->k; i++) {
        u32 portion_value = read_bits_as_4bytes(message_hash, i + 1, bit_slice_len);

        /* Current signature element (sk) */
        u8* current_signature_portion = &signature->signature[i * BITS_2_BYTES(hp->l)];

        /* Hash the current signature element (sk) for further comparison */
        u8 sk_hash[HASH_MAX_LENGTH_THRESHOLD];

#ifdef TVHASHOPTIMIZED
        TVOPTIMIZED_HORS_HASH_FUNCTION(sk_hash, current_signature_portion, BITS_2_BYTES(hp->l));
#else
        ltc_hash_sha2_256(sk_hash, current_signature_portion, BITS_2_BYTES(hp->l));
#endif
        /* Compare the hashed current signature element (sk) with public key indexed
         * by portion_value */
        if (memcmp(sk_hash,
                   &verifier->pk[portion_value * BITS_2_BYTES(hp->lpk)],
                   BITS_2_BYTES(hp->lpk)) != 0) {
#ifdef TIMEKEEPING
        gettimeofday(&end_time, NULL);
        hors_verify_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif
            return HORS_SIGNATURE_REJECTED;
        }
    }

#ifdef TIMEKEEPING
        gettimeofday(&end_time, NULL);
        hors_verify_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif
    return HORS_SIGNATURE_ACCEPTED;
}


u32 hors_new_hp(hors_hp_t* new_hp, const u8* config_file) {
    u8 line_buffer[CONFIG_FILE_MAX_LENGTH];

    read_file_line(line_buffer, CONFIG_FILE_MAX_LENGTH, NULL);

    //TODO change interface
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

            if (!strcmp(token, "t")) {
                if ((token = strtok(NULL, delim))) {
                    token = str_trim_char(token, '#');
                    new_hp->t = strtol(token, NULL, 10);
                } else
                    return HORS_NEW_HP_FAILED;

            } else if (!strcmp(token, "k")) {
                if ((token = strtok(NULL, delim))) {
                    token = str_trim_char(token, '#');
                    new_hp->k = strtol(token, NULL, 10);
                } else
                    return HORS_NEW_HP_FAILED;

            } else if (!strcmp(token, "lpk")) {
                if ((token = strtok(NULL, delim))) {
                    token = str_trim_char(token, '#');
                    new_hp->lpk = strtol(token, NULL, 10);
                } else
                    return HORS_NEW_HP_FAILED;

            } else if (!strcmp(token, "l")) {
                if ((token = strtok(NULL, delim))) {
                    token = str_trim_char(token, '#');
                    new_hp->l = strtol(token, NULL, 10);
                } else
                    return HORS_NEW_HP_FAILED;

            } else if (!strcmp(token, "rejection_sampling")) {
                if ((token = strtok(NULL, delim))) {
                    token = str_trim_char(token, '#');
                    if (strcmp(token, "true") == 0)
                        new_hp->do_rejection_sampling = 1;
                    else
                        new_hp->do_rejection_sampling = 0;
                } else
                    return HORS_NEW_HP_FAILED;
            } else if (!strcmp(token, "seed")) {
                if ((token = strtok(NULL, delim))) {
                    token = str_trim_char(token, '#');
                    new_hp->seed_file = malloc(strlen(token));
                    memcpy(new_hp->seed_file, token, strlen(token));
                } else
                    return HORS_NEW_HP_FAILED;
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

    return HORS_NEW_HP_SUCCESS;
}

void hors_destroy_hp(hors_hp_t* hp){
    free(hp->seed_file);
}

