CC=gcc
CFLAGS=-O2 -pipe -flto
#CFLAGS=-O0 -Wall -g3 -pedantic
BUILD_CFLAGS=-std=gnu99 -I. -D_FILE_OFFSET_BITS=64 -pipe
LDFLAGS=-flto -s -Wl,--gc-sections
#LDFLAGS=
FUSE_CFLAGS=$(shell pkg-config fuse --cflags)
FUSE_LDFLAGS=$(shell pkg-config fuse --libs)

LIBS=-lfuse

all: winregfs

winregfs: winregfs.o ntreg.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(FUSE_CFLAGS) $(CFLAGS) $(FUSE_LDFLAGS) -o mount.winregfs winregfs.o ntreg.o $(LIBS)

.c.o:
	$(CC) -c $(BUILD_CFLAGS) $(FUSE_CFLAGS) $(CFLAGS) $<

clean:
	rm -f *.o test *~ mount.winregfs debug.log

