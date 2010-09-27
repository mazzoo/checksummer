CC=diet gcc
CFLAGS=-Wall -O2
#CFLAGS+=-ggdb
CFLAGS+=-funroll-loops
#CFLAGS+=-funroll-all-loops
#CFLAGS+=-DCACHING

all:checksummer
clean:
	rm -f checksummer

dis:checksummer
	objdump -d -M intel checksummer > checksummer.asm
