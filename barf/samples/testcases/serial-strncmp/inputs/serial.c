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
    if (strncmp(serial,"serial",6)) {
        return 0;
    }

    /* tests passed */
    printf("Serial's fine!\n");

    return 0;
}
