#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define ERROR(x) do { perror(x); exit(-1); } while (0);

int main(int argc, char * argv[]) {
    char serial[256];
    int fd;

    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(-1);
    }

    if ((fd = open(argv[1], O_RDONLY)) == -1) {
        ERROR("open");
    }

    if (read(fd, &serial, 6) != 6) {
        ERROR("read");
    }

    if (close(fd) == -1) {
        ERROR("close");
    }

    /* check serial */
    if (serial[0] != 's') {
        return 0;
    }

    if (serial[1] != 'e') {
        return 0;
    }

    if (serial[2] != 'r') {
        return 0;
    }

    if (serial[3] != 'i') {
        return 0;
    }

    if (serial[4] != 'a') {
        return 0;
    }

    if (serial[5] != 'l') {
        return 0;
    }

    /* tests passed */
    printf("Serial's fine!\n");

    return 0;
}
