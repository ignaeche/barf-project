.PHONY: all clean

all: taint

taint: taint.c
	gcc -ggdb -m32 -o taint taint.c

clean:
	rm -f taint
