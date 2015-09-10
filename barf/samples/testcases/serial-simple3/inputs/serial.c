#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define ERROR(x) do { perror(x); exit(-1); } while (0);

char *serial = "serial";

int main(int argc, char * argv[]) {
    char data[256];
    int fd;
    int i;

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
    for (i = 0; i < 6; i++) {
        if (data[i] != serial[i]) {
            return 0;
        }
    }

    /* tests passed */
    printf("Serial's fine!\n");

    return 0;
}
