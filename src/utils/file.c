#include <bftvmhors/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

u32 read_file(u8 **output_buffer, u8 *file_name) {
    FILE *fp;

    if (!(fp = fopen(file_name, "r"))) return FILE_OPEN_ERROR;

    struct stat file_stat;
    stat(file_name, &file_stat);

    u8 *buffer = malloc(file_stat.st_size);
    fread(buffer, 1, file_stat.st_size, fp);
    *output_buffer = buffer;

    return file_stat.st_size;
}

u32 read_file_line(u8 *line, u32 line_size, u8 *file_name) {
    static FILE *fp;

    if (!file_name) {
        fp = NULL;
        /* Resetting the static variable is success */
        return FILE_OP_SUCCESS;
    }

    if (!fp && !(fp = fopen(file_name, "r"))) return FILE_OPEN_ERROR;

    /* Read line */
    if (!fgets(line, line_size, fp)) return FILE_READ_ERROR;

    return FILE_OP_SUCCESS;
}
