#ifndef BFTVMHORS_FORMAT_H
#define BFTVMHORS_FORMAT_H

#include <bftvmhors/types.h>



/// Concatenate two buffers into one
/// \param output Output buffer
/// \param buffer1 First buffer
/// \param len1 Length of the first buffer
/// \param buffer2 Second buffer
/// \param len2 Length of the second buffer
/// \return Length of the result
u64 concat_buffers(u8 * output, u8 * buffer1, u32 len1, u8 * buffer2, u32 len2);



#endif//BFTVMHORS_FORMAT_H
