CC=gcc
CFLAGS=-O2 -pipe -flto
#CFLAGS=-O0 -Wall -g3 -pedantic
BUILD_CFLAGS=-std=gnu99 -I. -D_FILE_OFFSET_BITS=64 -pipe
LDFLAGS=-flto -s
#LDFLAGS=
FUSE_CFLAGS=$(shell pkg-config fuse --cflags)
FUSE_LDFLAGS=$(shell pkg-config fuse --libs)
FUSE_LIBS=-lfuse

prefix=/usr
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
mandir=${prefix}/man
datarootdir=${prefix}/share
datadir=${datarootdir}
sysconfdir=${prefix}/etc

all: mount.winregfs fsck.winregfs manual

mount.winregfs: winregfs.o ntreg.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(FUSE_CFLAGS) $(BUILD_CFLAGS) $(FUSE_LDFLAGS) -o mount.winregfs winregfs.o ntreg.o $(FUSE_LIBS)

fsck.winregfs: fsck_winregfs.o ntreg.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(BUILD_CFLAGS) -o fsck.winregfs fsck_winregfs.o ntreg.o

manual:
	gzip -9 < mount.winregfs.8 > mount.winregfs.8.gz

.c.o:
	$(CC) -c $(BUILD_CFLAGS) $(FUSE_CFLAGS) $(CFLAGS) $<

clean:
	rm -f *.o *~ mount.winregfs fsck.winregfs debug.log *.?.gz

install: all
	install -D -o root -g root -m 0644 mount.winregfs.8.gz $(DESTDIR)/$(mandir)/man8/mount.winregfs.8.gz
#	install -D -o root -g root -m 0644 fsck.winregfs.8.gz $(DESTDIR)/$(mandir)/man8/fsck.winregfs.8.gz
	install -D -o root -g root -m 0755 -s mount.winregfs $(DESTDIR)/$(bindir)/mount.winregfs
	install -D -o root -g root -m 0755 -s fsck.winregfs $(DESTDIR)/$(bindir)/fsck.winregfs

