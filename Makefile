CC?=cc
CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -I./bearssl/inc
LDFLAGS+=-L./bearssl/build -lbearssl
DESTDIR?=

BINARIES=loadpem
BINARIES+=parseasn1
BINARIES+=tlswrapper

all: bearssl $(BINARIES)

alloc.o: alloc.c randombytes.h alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c alloc.c

blocking.o: blocking.c blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c blocking.c

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

loadpem.o: loadpem.c randombytes.h log.h alloc.h tls.h fsyncfile.h \
 writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c loadpem.c

log.o: log.c e.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c log.c

main_tlswrapper.o: main_tlswrapper.c blocking.h pipe.h log.h e.h jail.h \
 randombytes.h alloc.h connectioninfo.h proxyprotocol.h iptostr.h \
 writeall.h fixname.h tls.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper.c

main_tlswrapper_tcp.o: main_tlswrapper_tcp.c randombytes.h resolvehost.h \
 strtoport.h socket.h e.h log.h conn.h tls.h jail.h randommod.h main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_tcp.c

milliseconds.o: milliseconds.c milliseconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c milliseconds.c

parseasn1.o: parseasn1.c tls.h log.h alloc.h fsyncfile.h writeall.h \
 randombytes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c parseasn1.c

pipe.o: pipe.c e.h readall.h writeall.h alloc.h pipe.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pipe.c

porttostr.o: porttostr.c porttostr.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c porttostr.c

proxyprotocol.o: proxyprotocol.c strtoip.h iptostr.h porttostr.h \
 strtoport.h proxyprotocol.h
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

socket.o: socket.c blocking.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket.c

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

tls_error.o: tls_error.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_error.c

tls_keyjail.o: tls_keyjail.c pipe.h randombytes.h log.h jail.h fixpath.h \
 tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keyjail.c

tls_keytype.o: tls_keytype.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keytype.c

tls_pem.o: tls_pem.c alloc.h readall.h randombytes.h log.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pem.c

tls_pipe.o: tls_pipe.c tls.h pipe.h randombytes.h alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pipe.c

tls_profile.o: tls_profile.c log.h randombytes.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_profile.c

tls_pubcrt.o: tls_pubcrt.c randombytes.h alloc.h log.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pubcrt.c

tls_seccrt.o: tls_seccrt.c log.h randombytes.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_seccrt.c

tls_timeout.o: tls_timeout.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_timeout.c

tls_version.o: tls_version.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_version.c

tlswrapper.o: tlswrapper.c main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tlswrapper.c

writeall.o: writeall.c e.h jail.h writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c writeall.c

OBJECTS=alloc.o
OBJECTS+=blocking.o
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
OBJECTS+=main_tlswrapper_tcp.o
OBJECTS+=milliseconds.o
OBJECTS+=pipe.o
OBJECTS+=porttostr.o
OBJECTS+=proxyprotocol.o
OBJECTS+=randombytes.o
OBJECTS+=randommod.o
OBJECTS+=readall.o
OBJECTS+=resolvehost.o
OBJECTS+=socket.o
OBJECTS+=strtoip.o
OBJECTS+=strtoport.o
OBJECTS+=tls_anchor.o
OBJECTS+=tls_certfile.o
OBJECTS+=tls_cipher.o
OBJECTS+=tls_crypto_scalarmult.o
OBJECTS+=tls_ecdhe.o
OBJECTS+=tls_ecdsa.o
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

loadpem: loadpem.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o loadpem loadpem.o $(OBJECTS) $(LDFLAGS)

parseasn1: parseasn1.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o parseasn1 parseasn1.o $(OBJECTS) $(LDFLAGS)

tlswrapper: tlswrapper.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o tlswrapper tlswrapper.o $(OBJECTS) $(LDFLAGS)


bearssl:
	echo 'int main(){}' > try.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o try.o $(LDFLAGS) try.c || (sh bearssl.sh; cd bearssl; make; rm build/*.so; )
	rm -f try.o try.c

tlswrapper-tcp: tlswrapper
	ln -s tlswrapper tlswrapper-tcp

install: tlswrapper tlswrapper-tcp
	install -D -m 0755 tlswrapper $(DESTDIR)/usr/bin/tlswrapper
	install -D -m 0755 tlswrapper-tcp $(DESTDIR)/usr/bin/tlswrapper-tcp

test: bearssl $(BINARIES)
	./test.sh

clean:
	rm -f *.o $(BINARIES) tlswrapper-tcp

