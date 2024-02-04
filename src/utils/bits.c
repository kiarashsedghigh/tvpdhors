#include <bftvmhors/bits.h>
#include <bftvmhors/types.h>
#include <stdio.h>
#include <string.h>

// TODO generalize?
u32 read_bits_as_4bytes(const u8* input, u32 nth, u32 bit_slice_len) {
  /* Getting the starting bit/byte indices of the desired slice */
  u32 target_slice_start_bit_index = (nth - 1) * bit_slice_len;
  u32 target_slice_start_byte_index = BITS_2_BYTES(target_slice_start_bit_index);
  u32 next_8bit_boundary = (target_slice_start_byte_index + 1) * 8;

  u32 result = 0;

  /* If the bit slice we need is in the target byte */
  if (next_8bit_boundary - target_slice_start_bit_index >= bit_slice_len) {
    u32 num_shifts_to_right = next_8bit_boundary - target_slice_start_bit_index - bit_slice_len;
    result = input[target_slice_start_byte_index] >> num_shifts_to_right;
    result &= (1 << bit_slice_len) - 1;
  } else {
    /*
     * In this case, we first read any bits in the first byte, so we can reach
     * an index which is 8-bit boundary. Then, we read the remaining bits.
     * */

    /* Read the whole remaining bits of the first byte of the slice */
    result = input[target_slice_start_byte_index];

    /* No shift to the right, only masking the bits on the left side of the slice */
    result &= (1 << (next_8bit_boundary - target_slice_start_bit_index - 1)) - 1;

    /* Reading the remaining bits of the slice */
    bit_slice_len -= next_8bit_boundary - target_slice_start_bit_index;
    u32 num_of_rem_bytes = bit_slice_len / 8;
    u32 num_of_rem_bits = bit_slice_len % 8;

    for (u32 i = 0; i < num_of_rem_bytes; i++) {
      result << 8;
      result |= input[next_8bit_boundary / 8 + i];
    }

    /* Adding the remaining bits to the result */
    result = result << num_of_rem_bits;
    result |= input[next_8bit_boundary / 8 + num_of_rem_bytes] >> (8 - num_of_rem_bits);
  }
  return result;
}
