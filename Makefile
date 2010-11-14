CC=diet gcc
CFLAGS=-Wall -O2
#CFLAGS+=-ggdb
CFLAGS+=-funroll-loops
#CFLAGS+=-funroll-all-loops
#CFLAGS+=-DCACHING
#CFLAGS+=-DEXIT_AFTER_1ST_CHECKSUM_FOUND

checksummer:checksummer.o indexer.c

all:checksummer

clean:
	rm -f checksummer
	rm -f checksummer.o
	rm -f indexer.o

dis:checksummer
	objdump -d -M intel checksummer > checksummer.asm
