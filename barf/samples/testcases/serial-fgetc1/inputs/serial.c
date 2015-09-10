#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define ERROR(x) do { perror(x); exit(-1); } while (0);

int main(int argc, char * argv[]) {
    FILE *file;

    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(-1);
    }

    if (!(file = fopen(argv[1], "r"))) {
        ERROR("fopen");
    }

    /* check serial */
    if ((unsigned char) fgetc(file) != 's') {
        goto fail;
    }

    if ((unsigned char) fgetc(file) != 'e') {
        goto fail;
    }

    if ((unsigned char) fgetc(file) != 'r') {
        goto fail;
    }

    if ((unsigned char) fgetc(file) != 'i') {
        goto fail;
    }

    if ((unsigned char) fgetc(file) != 'a') {
        goto fail;
    }

    if ((unsigned char) fgetc(file) != 'l') {
        goto fail;
    }

    /* tests passed */
    printf("Serial's fine!\n");

fail:
    if (fclose(file)) {
        ERROR("fclose");
    }

    return 0;
}
