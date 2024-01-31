#include <bftvmhors/types.h>

u64 concat_buffers(u8 * output, u8 * buffer1, u32 len1, u8 * buffer2, u32 len2){
    for(u32 i=0; i<len1; i++)
        output[i]=buffer1[i];
    for(u32 i=0; i<len2; i++)
        output[len1 + i]=buffer2[i];

    return len1+len2;
}

//
//
//void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
//{
//    for (int i=0; i<inputlength; i++){
//        sprintf(&output[2*i], "%02x", input[i]);
//    }
//    printf("Hex format: %s\n", output);  //remove later
//}
//
//
//
//
//
//
//





