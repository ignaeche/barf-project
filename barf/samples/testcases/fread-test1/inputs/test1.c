#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define ERROR(x) do { perror(x); exit(-1); } while (0);

int main(int argc, char * argv[]) {
    FILE *file;
    char value;

    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(-1);
    }

    if (!(file = fopen(argv[1], "r"))) {
        ERROR("fopen");
    }

    if (fread(&value, sizeof value, 1, file) == -1) {
        ERROR("fread");
    }

    if (value != 's') {
        goto fail;
    }

    if (fread(&value, sizeof value, 1, file) == -1) {
        ERROR("fread");
    }

    if (value != 'e') {
        goto fail;
    }

    if (fread(&value, sizeof value, 1, file) == -1) {
        ERROR("fread");
    }

    if (value != 'r') {
        goto fail;
    }

    if (fread(&value, sizeof value, 1, file) == -1) {
        ERROR("fread");
    }

    if (value != 'i') {
        goto fail;
    }

    if (fread(&value, sizeof value, 1, file) == -1) {
        ERROR("fread");
    }

    if (value != 'a') {
        goto fail;
    }

    if (fread(&value, sizeof value, 1, file) == -1) {
        ERROR("fread");
    }

    if (value != 'l') {
        goto fail;
    }

    /* tests passed */
    printf("Test passed!\n");

fail:
    if (fclose(file)) {
        ERROR("fclose");
    }

    return 0;
}
