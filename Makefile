CC?=cc
EMPTYDIR?=/var/lib/tlswrapper/empty
CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -DEMPTYDIR=\"$(EMPTYDIR)\"
LDFLAGS+=-lbearssl
CPPFLAGS?=

DESTDIR?=
PREFIX?=/usr/local

INSTALL?=install

BINARIES=tlswrapper
BINARIES+=tlswrapper-test

all: $(BINARIES) tlswrapper-tcp tlswrapper-smtp

alloc.o: alloc.c log.h alloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c alloc.c

blocking.o: blocking.c blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c blocking.c

buffer.o: buffer.c buffer.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c buffer.c

case.o: case.c case.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c case.c

conn.o: conn.c jail.h socket.h milliseconds.h e.h log.h conn.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c conn.c

connectioninfo.o: connectioninfo.c strtoip.h strtoport.h porttostr.h \
 iptostr.h log.h connectioninfo.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c connectioninfo.c

e.o: e.c e.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c e.c

fixname.o: fixname.c fixname.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c fixname.c

fixpath.o: fixpath.c fixpath.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c fixpath.c

fsyncfile.o: fsyncfile.c fsyncfile.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c fsyncfile.c

hostport.o: hostport.c strtoport.h hostport.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c hostport.c

iptostr.o: iptostr.c iptostr.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c iptostr.c

jail.o: jail.c log.h randommod.h jail.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c jail.c

jail_poll.o: jail_poll.c log.h jail.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c jail_poll.c

log.o: log.c e.h randommod.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c log.c

main_tlswrapper.o: main_tlswrapper.c blocking.h pipe.h log.h e.h jail.h \
 strtonum.h randombytes.h haslibrandombytes.h alloc.h connectioninfo.h \
 proxyprotocol.h iptostr.h writeall.h fixname.h fixpath.h str.h tls.h \
 open.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper.c

main_tlswrapper_smtp.o: main_tlswrapper_smtp.c randombytes.h \
 haslibrandombytes.h log.h iptostr.h connectioninfo.h jail.h writeall.h \
 buffer.h stralloc.h open.h e.h tls.h blocking.h resolvehost.h hostport.h \
 conn.h case.h timeoutwrite.h timeoutread.h strtonum.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_smtp.c

main_tlswrapper_tcp.o: main_tlswrapper_tcp.c randombytes.h \
 haslibrandombytes.h iptostr.h proxyprotocol.h connectioninfo.h \
 resolvehost.h strtoport.h socket.h e.h log.h conn.h str.h tls.h jail.h \
 randommod.h strtonum.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_tcp.c

main_tlswrapper_test.o: main_tlswrapper_test.c e.h log.h randombytes.h \
 haslibrandombytes.h fsyncfile.h writeall.h str.h tls.h open.h blocking.h \
 strtonum.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_test.c

milliseconds.o: milliseconds.c milliseconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c milliseconds.c

open_pipe.o: open_pipe.c open.h blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c open_pipe.c

open_read.o: open_read.c open.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c open_read.c

pipe.o: pipe.c e.h readall.h writeall.h alloc.h pipe.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pipe.c

porttostr.o: porttostr.c porttostr.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c porttostr.c

proxyprotocol.o: proxyprotocol.c e.h log.h str.h buffer.h stralloc.h \
 jail.h iptostr.h strtoip.h strtoport.h porttostr.h proxyprotocol.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c proxyprotocol.c

randombytes.o: randombytes.c randombytes.h haslibrandombytes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randombytes.c

randommod.o: randommod.c randombytes.h haslibrandombytes.h randommod.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randommod.c

readall.o: readall.c e.h readall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c readall.c

resolvehost.o: resolvehost.c e.h blocking.h log.h jail.h randommod.h \
 resolvehost.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c resolvehost.c

socket.o: socket.c blocking.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket.c

stralloc.o: stralloc.c alloc.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c stralloc.c

str.o: str.c str.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c str.c

strtoip.o: strtoip.c strtoip.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c strtoip.c

strtonum.o: strtonum.c strtonum.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c strtonum.c

strtoport.o: strtoport.c strtoport.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c strtoport.c

timeoutread.o: timeoutread.c timeoutread.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c timeoutread.c

timeoutwrite.o: timeoutwrite.c timeoutwrite.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c timeoutwrite.c

tls_anchor.o: tls_anchor.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_anchor.c

tls_certfile.o: tls_certfile.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_certfile.c

tls_cipher.o: tls_cipher.c str.h log.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_cipher.c

tls_crypto_scalarmult.o: tls_crypto_scalarmult.c tls.h haslib25519.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_crypto_scalarmult.c

tls_ecdhe.o: tls_ecdhe.c str.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_ecdhe.c

tls_ecdsa.o: tls_ecdsa.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_ecdsa.c

tls_engine.o: tls_engine.c writeall.h log.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_engine.c

tls_error.o: tls_error.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_error.c

tls_keyjail.o: tls_keyjail.c pipe.h randombytes.h haslibrandombytes.h \
 log.h jail.h fixpath.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keyjail.c

tls_keytype.o: tls_keytype.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keytype.c

tls_pem.o: tls_pem.c alloc.h readall.h randombytes.h haslibrandombytes.h \
 log.h open.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pem.c

tls_pipe.o: tls_pipe.c tls.h pipe.h randombytes.h haslibrandombytes.h \
 alloc.h str.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pipe.c

tls_profile.o: tls_profile.c log.h randombytes.h haslibrandombytes.h e.h \
 str.h stralloc.h fixpath.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_profile.c

tls_pubcrt.o: tls_pubcrt.c randombytes.h haslibrandombytes.h alloc.h \
 log.h stralloc.h str.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pubcrt.c

tls_seccrt.o: tls_seccrt.c log.h randombytes.h haslibrandombytes.h str.h \
 tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_seccrt.c

tls_version.o: tls_version.c str.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_version.c

tlswrapper.o: tlswrapper.c str.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tlswrapper.c

tlswrapper-test.o: tlswrapper-test.c str.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tlswrapper-test.c

writeall.o: writeall.c e.h jail.h writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c writeall.c

OBJECTS=alloc.o
OBJECTS+=blocking.o
OBJECTS+=buffer.o
OBJECTS+=case.o
OBJECTS+=conn.o
OBJECTS+=connectioninfo.o
OBJECTS+=e.o
OBJECTS+=fixname.o
OBJECTS+=fixpath.o
OBJECTS+=fsyncfile.o
OBJECTS+=hostport.o
OBJECTS+=iptostr.o
OBJECTS+=jail.o
OBJECTS+=jail_poll.o
OBJECTS+=log.o
OBJECTS+=main_tlswrapper.o
OBJECTS+=main_tlswrapper_smtp.o
OBJECTS+=main_tlswrapper_tcp.o
OBJECTS+=main_tlswrapper_test.o
OBJECTS+=milliseconds.o
OBJECTS+=open_pipe.o
OBJECTS+=open_read.o
OBJECTS+=pipe.o
OBJECTS+=porttostr.o
OBJECTS+=proxyprotocol.o
OBJECTS+=randombytes.o
OBJECTS+=randommod.o
OBJECTS+=readall.o
OBJECTS+=resolvehost.o
OBJECTS+=socket.o
OBJECTS+=stralloc.o
OBJECTS+=str.o
OBJECTS+=strtoip.o
OBJECTS+=strtonum.o
OBJECTS+=strtoport.o
OBJECTS+=timeoutread.o
OBJECTS+=timeoutwrite.o
OBJECTS+=tls_anchor.o
OBJECTS+=tls_certfile.o
OBJECTS+=tls_cipher.o
OBJECTS+=tls_crypto_scalarmult.o
OBJECTS+=tls_ecdhe.o
OBJECTS+=tls_ecdsa.o
OBJECTS+=tls_engine.o
OBJECTS+=tls_error.o
OBJECTS+=tls_keyjail.o
OBJECTS+=tls_keytype.o
OBJECTS+=tls_pem.o
OBJECTS+=tls_pipe.o
OBJECTS+=tls_profile.o
OBJECTS+=tls_pubcrt.o
OBJECTS+=tls_seccrt.o
OBJECTS+=tls_version.o
OBJECTS+=writeall.o

tlswrapper: tlswrapper.o $(OBJECTS) libs
	$(CC) $(CFLAGS) $(CPPFLAGS) -o tlswrapper tlswrapper.o $(OBJECTS) $(LDFLAGS) `cat libs`

tlswrapper-test: tlswrapper-test.o $(OBJECTS) libs
	$(CC) $(CFLAGS) $(CPPFLAGS) -o tlswrapper-test tlswrapper-test.o $(OBJECTS) $(LDFLAGS) `cat libs`


haslib25519.h: tryfeature.sh haslib25519.c libs
	env CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS) `cat libs`" ./tryfeature.sh haslib25519.c > haslib25519.h
	cat haslib25519.h

haslibrandombytes.h: tryfeature.sh haslibrandombytes.c libs
	env CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS) `cat libs`" ./tryfeature.sh haslibrandombytes.c > haslibrandombytes.h
	cat haslibrandombytes.h

libs: trylibs.sh
	env CC="$(CC)" ./trylibs.sh -lsocket -lnsl -lrandombytes -l25519 >libs 2>libs.log
	cat libs

tlswrapper-tcp: tlswrapper
	ln -s tlswrapper tlswrapper-tcp

tlswrapper-smtp: tlswrapper
	ln -s tlswrapper tlswrapper-smtp

install: $(BINARIES) tlswrapper-tcp tlswrapper-smtp
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	mkdir -p $(DESTDIR)$(EMPTYDIR)
	$(INSTALL) -m 0755 tlswrapper $(DESTDIR)$(PREFIX)/bin/tlswrapper
	$(INSTALL) -m 0755 tlswrapper-tcp $(DESTDIR)$(PREFIX)/bin/tlswrapper-tcp
	$(INSTALL) -m 0755 tlswrapper-smtp $(DESTDIR)$(PREFIX)/bin/tlswrapper-smtp
	$(INSTALL) -m 0644 man/tlswrapper.1 $(DESTDIR)$(PREFIX)/share/man/man1/tlswrapper.1
	$(INSTALL) -m 0644 man/tlswrapper-smtp.1 $(DESTDIR)$(PREFIX)/share/man/man1/tlswrapper-smtp.1
	$(INSTALL) -m 0644 man/tlswrapper-tcp.1 $(DESTDIR)$(PREFIX)/share/man/man1/tlswrapper-tcp.1

test: $(BINARIES) tlswrapper-tcp tlswrapper-smtp
	sh runtest.sh test-cipher.sh test-cipher.out test-cipher.exp
	sh runtest.sh test-ephemeral.sh test-ephemeral.out test-ephemeral.exp
	sh runtest.sh test-options.sh test-options.out test-options.exp
	sh runtest.sh test-pp.sh test-pp.out test-pp.exp
	sh runtest.sh test-badcert.sh test-badcert.out test-badcert.exp
	sh runtest.sh test-badkey.sh test-badkey.out test-badkey.exp
	sh runtest.sh test-childexit.sh test-childexit.out test-childexit.exp
	sh runtest.sh test-okcert.sh test-okcert.out test-okcert.exp

clean:
	rm -f *.log *.o *.out $(BINARIES) libs tlswrapper-tcp tlswrapper-smtp has*.h

