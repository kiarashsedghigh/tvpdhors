#include <bftvmhors/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>


u32 read_file(u8 ** output_buffer, u8 * file_name){
    FILE * fp;

    if (!(fp = fopen(file_name,"r")))
        return 0;

    struct stat file_stat;
    stat(file_name,&file_stat);
    u8 * buffer = malloc(file_stat.st_size);

    fread(buffer,1 , file_stat.st_size, fp); //TODO check for the error


    *output_buffer = buffer;
    return file_stat.st_size;
}


u32 read_file_line(u8 * line, u32 line_size, u8 * file_name){
    static FILE * fp;

    if (!file_name){
        fp = NULL;
        return 1;
    }

    if (!fp)
        if (!(fp = fopen(file_name,"r")))
            return 1;

    /* Read line */
    if (!fgets(line, line_size, fp))
        return 1;

    return 0;
}
















