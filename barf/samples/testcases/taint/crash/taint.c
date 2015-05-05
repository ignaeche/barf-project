#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define ERROR(x) do { perror(x); exit(-1); } while (0);

int main(int argc, char *argv[]) {
    char data;
    int fd;

    if (argc != 2) {
        printf("Usage: %s <file>\n", argv[0]);
        exit(-1);
    }

    if ((fd = open(argv[1], O_RDONLY)) == -1) {
        ERROR("open");
    }

    if (read(fd, &data, 1) != 1) {
        ERROR("read");
    }

    if (close(fd) == -1) {
        ERROR("close");
    }

    if (data == 0x41) {
        printf("ok\n");
    }

    return 0;
}
