# YAKU-NS Makefile
#
# Copyright (C) 2000 by Salvatore Sanfilippo
# <antirez@invece.org>

.SUFFIXES:
.SUFFIXES: .c .o

SHELL= /bin/sh
CFLAGS= -W -Wall -O2 -g
AR=/usr/bin/ar

INSTALL= /usr/bin/install
INSTALL_PROGRAM= $(INSTALL)
INSTALL_DATA= $(INSTALL) -m 644
DESTDIR= /usr/local/bin/

PROGRAMS= yaku-ns getzone
YAKUNS_OBJECTS= acl.o arr.o axfr_out.o autoptr.o cache.o config.o core.o \
		dns.o forward.o local.o log.o htkey.o \
		misc.o unix.o uptime.o aht.o strlcpy.o strlcat.o \
		signal.o response.o rlimit.o
GETZONE_OBJECTS= getzone.o dns.o strlcpy.o

all: .depend yaku-ns getzone success

.depend:
	@echo Making dependences
	@$(CC) -MM *.c > .depend

.c.o:
	$(CC) -I. $(CFLAGS) $(DEFS) -c $< -o $@

yaku-ns:	$(YAKUNS_OBJECTS)
		$(CC) $(LDFLAGS) $^ -o $@

getzone:	$(GETZONE_OBJECTS)
		$(CC) $(LDFLAGS) $^ -o $@

strip:
	strip $(PROGRAMS)
	@ls -l $(PROGRAMS)

install:
	@echo See the INSTALL file

clean:
	rm -f *.o core .depend .nfs* */.nfs* .*.swp $(PROGRAMS)

success:
	@echo
	@echo Compilation successful!
	@echo Now you can read the INSTALL file

distclean:
mostlyclean:

dist: clean sign tar

tar:
	if [ "x" = "x$(RELEASE)" ]; then \
		d=`date -Iseconds | cut -d+ -f1 | tr -- :T -.`; \
		v=`grep VERSION tunable.h | cut -d\" -f2`; \
		b=`echo yaku-ns-$$v-$$d`; mkdir ../$$b; cp -a . ../$$b; \
		cd ..; read; tar cvzf $$b.tar.gz $$b; \
	else \
		v=`grep VERSION tunable.h | cut -d\" -f2`; \
		b=`echo yaku-ns-$$v`; mkdir ../$$b; cp -a . ../$$b; \
		cd ..; read; tar cvf - $$b | gzip -9 > $$b.tar.gz; \
		read; tar cvf - $$b | bzip2 -9 > $$b.tar.bz2; \
	fi; \
	ls -l $$b.tar.*

wc:
	cat *.[ch] | sed -e /^$$/d | wc -l

sign:
	rm -f MD5SUM.SIGNED*
	-(md5sum * 2> /dev/null > MD5SUM.SIGNED)
	pgp -sta MD5SUM.SIGNED
	rm -f MD5SUM.SIGNED

check:
	md5sum -vc MD5SUM.SIGNED.asc

ifeq (.depend,$(wildcard .depend))
include .depend
endif
