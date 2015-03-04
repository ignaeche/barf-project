#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define ERROR(x) do { perror(x); exit(-1); } while (0);

char *serial = "serial";

int main(int argc, char * argv[]) {
    char data[256];
    int fd;

    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(-1);
    }

    if ((fd = open(argv[1], O_RDONLY)) == -1) {
        ERROR("open");
    }

    if (read(fd, &data, 6) != 6) {
        ERROR("read");
    }

    if (close(fd) == -1) {
        ERROR("close");
    }

    /* check serial */
    if (data[0] != serial[0]) {
        return 0;
    }

    if (data[1] != serial[1]) {
        return 0;
    }

    if (data[2] != serial[2]) {
        return 0;
    }

    if (data[3] != serial[3]) {
        return 0;
    }

    if (data[4] != serial[4]) {
        return 0;
    }

    if (data[5] != serial[5]) {
        return 0;
    }

    /* tests passed */
    printf("Serial's fine!\n");

    return 0;
}
