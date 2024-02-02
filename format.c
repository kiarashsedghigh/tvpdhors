#include <bftvmhors/types.h>


u8 * str_ltrim(u8 * input){
    while(*input && (*input == ' ' || *input == '\t' || *input == '\n'))
        input++;
    return input;
}

void str_rtrim(u8 * input) {
    /* Go to the end of the string */
    while (*(input+1))
        input++;

    while (*input && (*input == ' ' || *input == '\t' || *input == '\n'))
        input--;

    *(input + 1) = 0;
}

u8 * str_trim(u8 * input){
    u8 * input_temp = input;

    /* Trim right */
    while (*(input+1))
        input++;
    while (*input && (*input == ' ' || *input == '\t' || *input == '\n'))
        input--;

    *(input + 1) = 0;


    /* Trim left */
    input=input_temp;

    while(*input && (*input == ' ' || *input == '\t' || *input == '\n'))
        input++;
    return input;

}


u8 * str_ltrim_char(u8 * input, u8 ch){
    while(*input && (*input == ' ' || *input == '\t' || *input == '\n' || *input == ch))
        input++;
    return input;
}

void str_rtrim_char(u8 * input, u8 ch) {
    /* Go to the end of the string */
    while (*(input+1))
        input++;

    while (*input && (*input == ' ' || *input == '\t' || *input == '\n' || *input == ch))
        input--;

    *(input + 1) = 0;
}

u8 * str_trim_char(u8 * input, u8 ch){
    u8 * input_temp = input;

    /* Trim right */
    while (*(input+1))
        input++;
    while (*input && (*input == ' ' || *input == '\t' || *input == '\n' || *input == ch))
        input--;

    *(input + 1) = 0;


    /* Trim left */
    input=input_temp;

    while(*input && (*input == ' ' || *input == '\t' || *input == '\n'))
        input++;
    return input;

}




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





