CFLAGS=-Wall -O2
#CFLAGS+=-ggdb
#CFLAGS+=-funroll-loops
CFLAGS+=-funroll-all-loops

all:checksummer
clean:
	rm -f checksummer
