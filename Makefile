CC?=cc
EMPTYDIR?=/var/lib/tlswrapper/empty
CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -I./bearssl/inc -DEMPTYDIR=\"$(EMPTYDIR)\"
LDFLAGS+=-L./bearssl/build -lbearssl
DESTDIR?=

BINARIES=escape
BINARIES+=tlswrapper
BINARIES+=tlswrapper-test

all: bearssl $(BINARIES) tlswrapper-tcp tlswrapper-smtptest

alloc.o: alloc.c randombytes.h alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c alloc.c

blocking.o: blocking.c blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c blocking.c

buf.o: buf.c buf.h iptostr.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c buf.c

commands.o: commands.c sio.h stralloc.h commands.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c commands.c

conn.o: conn.c jail.h socket.h milliseconds.h e.h log.h conn.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c conn.c

connectioninfo.o: connectioninfo.c strtoip.h strtoport.h porttostr.h \
 iptostr.h log.h connectioninfo.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c connectioninfo.c

crypto_scalarmult_curve25519.o: crypto_scalarmult_curve25519.c \
 crypto_scalarmult_curve25519.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_scalarmult_curve25519.c

e.o: e.c e.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c e.c

escape.o: escape.c e.h log.h writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c escape.c

fixname.o: fixname.c fixname.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c fixname.c

fixpath.o: fixpath.c fixpath.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c fixpath.c

fsyncfile.o: fsyncfile.c fsyncfile.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c fsyncfile.c

iptostr.o: iptostr.c iptostr.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c iptostr.c

jail.o: jail.c log.h randommod.h jail.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c jail.c

jail_poll.o: jail_poll.c log.h jail.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c jail_poll.c

log.o: log.c e.h randommod.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c log.c

main_tlswrapper.o: main_tlswrapper.c blocking.h pipe.h log.h e.h jail.h \
 randombytes.h alloc.h connectioninfo.h proxyprotocol.h iptostr.h \
 writeall.h fixname.h fixpath.h tls.h open.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper.c

main_tlswrapper_smtp.o: main_tlswrapper_smtp.c randombytes.h sio.h \
 commands.h log.h open.h stralloc.h e.h blocking.h iptostr.h \
 connectioninfo.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_smtp.c

main_tlswrapper_smtptest.o: main_tlswrapper_smtptest.c randombytes.h \
 commands.h sio.h log.h open.h stralloc.h e.h blocking.h main.h \
 writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_smtptest.c

main_tlswrapper_tcp.o: main_tlswrapper_tcp.c randombytes.h iptostr.h \
 proxyprotocol.h connectioninfo.h resolvehost.h strtoport.h socket.h e.h \
 log.h conn.h tls.h jail.h randommod.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_tcp.c

main_tlswrapper_test.o: main_tlswrapper_test.c e.h log.h randombytes.h \
 fsyncfile.h writeall.h tls.h open.h blocking.h main.h
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

proxyprotocol.o: proxyprotocol.c jail.h buf.h e.h log.h strtoip.h \
 strtoport.h iptostr.h porttostr.h proxyprotocol.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c proxyprotocol.c

randombytes.o: randombytes.c log.h randombytes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randombytes.c

randommod.o: randommod.c randombytes.h randommod.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randommod.c

readall.o: readall.c e.h readall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c readall.c

resolvehost.o: resolvehost.c e.h blocking.h log.h jail.h randommod.h \
 resolvehost.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c resolvehost.c

sa.o: sa.c alloc.h sa.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c sa.c

sio.o: sio.c e.h jail.h sio.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c sio.c

socket.o: socket.c blocking.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket.c

stralloc.o: stralloc.c alloc.h e.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c stralloc.c

strtoip.o: strtoip.c strtoip.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c strtoip.c

strtoport.o: strtoport.c strtoport.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c strtoport.c

tls_anchor.o: tls_anchor.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_anchor.c

tls_certfile.o: tls_certfile.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_certfile.c

tls_cipher.o: tls_cipher.c log.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_cipher.c

tls_crypto_scalarmult.o: tls_crypto_scalarmult.c tls.h \
 crypto_scalarmult_curve25519.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_crypto_scalarmult.c

tls_ecdhe.o: tls_ecdhe.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_ecdhe.c

tls_ecdsa.o: tls_ecdsa.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_ecdsa.c

tls_engine.o: tls_engine.c writeall.h log.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_engine.c

tls_error.o: tls_error.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_error.c

tls_keyjail.o: tls_keyjail.c pipe.h randombytes.h log.h jail.h fixpath.h \
 tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keyjail.c

tls_keytype.o: tls_keytype.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keytype.c

tls_pem.o: tls_pem.c alloc.h readall.h randombytes.h log.h open.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pem.c

tls_pipe.o: tls_pipe.c tls.h pipe.h randombytes.h alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pipe.c

tls_profile.o: tls_profile.c log.h randombytes.h e.h buf.h fixpath.h \
 tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_profile.c

tls_pubcrt.o: tls_pubcrt.c randombytes.h alloc.h log.h sa.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pubcrt.c

tls_seccrt.o: tls_seccrt.c log.h randombytes.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_seccrt.c

tls_timeout.o: tls_timeout.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_timeout.c

tls_version.o: tls_version.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_version.c

tlswrapper.o: tlswrapper.c main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tlswrapper.c

tlswrapper-test.o: tlswrapper-test.c main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tlswrapper-test.c

writeall.o: writeall.c e.h jail.h writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c writeall.c

OBJECTS=alloc.o
OBJECTS+=blocking.o
OBJECTS+=buf.o
OBJECTS+=commands.o
OBJECTS+=conn.o
OBJECTS+=connectioninfo.o
OBJECTS+=crypto_scalarmult_curve25519.o
OBJECTS+=e.o
OBJECTS+=fixname.o
OBJECTS+=fixpath.o
OBJECTS+=fsyncfile.o
OBJECTS+=iptostr.o
OBJECTS+=jail.o
OBJECTS+=jail_poll.o
OBJECTS+=log.o
OBJECTS+=main_tlswrapper.o
OBJECTS+=main_tlswrapper_smtp.o
OBJECTS+=main_tlswrapper_smtptest.o
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
OBJECTS+=sa.o
OBJECTS+=sio.o
OBJECTS+=socket.o
OBJECTS+=stralloc.o
OBJECTS+=strtoip.o
OBJECTS+=strtoport.o
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
OBJECTS+=tls_timeout.o
OBJECTS+=tls_version.o
OBJECTS+=writeall.o

escape: escape.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o escape escape.o $(OBJECTS) $(LDFLAGS)

tlswrapper: tlswrapper.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o tlswrapper tlswrapper.o $(OBJECTS) $(LDFLAGS)

tlswrapper-test: tlswrapper-test.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o tlswrapper-test tlswrapper-test.o $(OBJECTS) $(LDFLAGS)


bearssl:
	echo 'int main(){}' > try.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o try.o $(LDFLAGS) try.c || (sh bearssl.sh; cd bearssl; make; rm build/*.so; )
	rm -f try.o try.c
	mkdir -p bearssl/inc

tlswrapper-tcp: tlswrapper
	ln -s tlswrapper tlswrapper-tcp

tlswrapper-smtp: tlswrapper
	ln -s tlswrapper tlswrapper-smtp

tlswrapper-smtptest: tlswrapper
	ln -s tlswrapper tlswrapper-smtptest

install: $(BINARIES) tlswrapper-tcp
	install -D -m 0755 tlswrapper $(DESTDIR)/usr/bin/tlswrapper
	install -D -m 0755 tlswrapper-tcp $(DESTDIR)/usr/bin/tlswrapper-tcp
	install -D -m 0755 tlswrapper-smtp $(DESTDIR)/usr/bin/tlswrapper-smtp
	install -d -m 0755 $(DESTDIR)/$(EMPTYDIR)

test: bearssl $(BINARIES) tlswrapper-tcp escape
	sh runtest.sh test-cipher.sh test-cipher.out test-cipher.exp
	sh runtest.sh test-ephemeral.sh test-ephemeral.out test-ephemeral.exp
	sh runtest.sh test-options.sh test-options.out test-options.exp
	sh runtest.sh test-pp.sh test-pp.out test-pp.exp
	sh runtest.sh test-badcert.sh test-badcert.out test-badcert.exp
	sh runtest.sh test-badkey.sh test-badkey.out test-badkey.exp
	sh runtest.sh test-childexit.sh test-childexit.out test-childexit.exp
	sh runtest.sh test-okcert.sh test-okcert.out test-okcert.exp

clean:
	rm -f *.o *.out $(BINARIES) tlswrapper-tcp tlswrapper-smtp tlswrapper-smtptest

