#include <bftvmhors/types.h>
#include <bftvmhors/bits.h>
#include <stdio.h>
#include <string.h>

//TODO generalize?
u32 read_bits_as_4bytes(const u8 * input, u32 nth, u32 bit_slice_len){

    u32 target_bit_slice_start_index = (nth-1) * bit_slice_len;

    u32 target_byte_start_index = BITS_2_BYTES(target_bit_slice_start_index);

    u32 next_8bit_boundary = (target_byte_start_index+1)*8;

    u32 result = 0;

    /* If the total bits we need are in the current target byte */
    if (next_8bit_boundary - target_bit_slice_start_index >= bit_slice_len){
        u32 num_shift_to_left = next_8bit_boundary - target_bit_slice_start_index - bit_slice_len;

        result = input[target_byte_start_index] >> num_shift_to_left;
        result &= (1 << bit_slice_len) - 1; // Keep the right most bits with size bit_slice_len
    }else{
        /* Read the whole remaining bits of the current byte */
        result = input[target_byte_start_index];

        /* No shift to the right, only masking the left bits */
        result &= (1 << (next_8bit_boundary - target_bit_slice_start_index-1))  - 1;

        /* Reading the remaining bits */
        bit_slice_len -= next_8bit_boundary - target_bit_slice_start_index;

        u32 num_of_rem_bytes = bit_slice_len / 8;
        u32 num_of_rem_bits = bit_slice_len % 8;

        for (u32 i=0; i<num_of_rem_bytes; i++){
            result << 8;
            result |= input[next_8bit_boundary/8 + i];
        }

        // Adding the remaining bits
        result = result << num_of_rem_bits;
        result |= input[next_8bit_boundary/8 + num_of_rem_bytes] >> (8 - num_of_rem_bits);
    }
    return result;
}



u32 pad_with_zero(u8 * output, u8 * input, u32 input_len, u32 boundary_coefficient){
    u32 num_bits_to_add = (input_len % boundary_coefficient ==0) ? 0 : ((input_len/boundary_coefficient)+1)*boundary_coefficient - input_len;
    u32 num_bytes_to_add =  (num_bits_to_add % 8 ==0 ) ? num_bits_to_add/8 : num_bits_to_add/8+1;

    u8 zero= 0;
    memcpy(output, input, input_len);
    memcpy(output+input_len, &zero, num_bytes_to_add);

    return input_len + num_bytes_to_add;
}