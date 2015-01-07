#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>

char *serial = "\x30\x39\x3c\x21\x30";

int main(void)
{
  int fd, i = 0;
  char buf[260] = {0};
  char *r = buf;

  fd = open("serial.txt", O_RDONLY);
  read(fd, r, 256);
  close(fd);
  while (i < 5){
    if ((*r ^ 0x55) != *serial)
      return 0;
    r++, serial++, i++;
  }
  if (!*r)
    printf("Good boy\n");
  return 0;
}
