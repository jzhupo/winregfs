CC=gcc
CFLAGS=-O2 -pipe -flto
#CFLAGS=-O0 -Wall -g3 -pedantic
BUILD_CFLAGS=-std=gnu99 -I. -D_FILE_OFFSET_BITS=64 -pipe
LDFLAGS=-flto -s
LDFLAGS=
FUSE_CFLAGS=$(shell pkg-config fuse --cflags)
FUSE_LDFLAGS=$(shell pkg-config fuse --libs)
LIBS=-lfuse

prefix=/usr
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
mandir=${prefix}/man
datarootdir=${prefix}/share
datadir=${datarootdir}
sysconfdir=${prefix}/etc

all: mount.winregfs

mount.winregfs: winregfs.o ntreg.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(FUSE_CFLAGS) $(CFLAGS) $(FUSE_LDFLAGS) -o mount.winregfs winregfs.o ntreg.o $(LIBS)

.c.o:
	$(CC) -c $(BUILD_CFLAGS) $(FUSE_CFLAGS) $(CFLAGS) $<

clean:
	rm -f *.o *~ mount.winregfs debug.log

install: all
#	install -D -o root -g root -m 0644 mount.winregfs.1.gz $(DESTDIR)/$(mandir)/man8/mount.winregfs.8.gz
	install -D -o root -g root -m 0755 -s mount.winregfs $(DESTDIR)/$(bindir)/mount.winregfs

