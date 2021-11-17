CC=gcc
CFLAGS+=-W -Wall -Os -fPIC -fwrapv -Wall -I/usr/include/bearssl
LDFLAGS+=-lbearssl

BINARIES+=testalloc
BINARIES+=testchacha20
BINARIES+=testjail
BINARIES+=testrandombytes
BINARIES+=tlswrapper

all: $(BINARIES)

alloc.o: alloc.c randombytes.h alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c alloc.c

blocking.o: blocking.c blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c blocking.c

conn.o: conn.c jail.h socket.h nanoseconds.h e.h log.h conn.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c conn.c

crypto_scalarmult_curve25519.o: crypto_scalarmult_curve25519.c \
 crypto_scalarmult_curve25519.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_scalarmult_curve25519.c

e.o: e.c e.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c e.c

fsyncfile.o: fsyncfile.c fsyncfile.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c fsyncfile.c

jail.o: jail.c log.h randommod.h jail.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c jail.c

jail_poll.o: jail_poll.c log.h jail.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c jail_poll.c

log.o: log.c e.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c log.c

main_tlswrapper.o: main_tlswrapper.c blocking.h pipe.h log.h e.h jail.h \
 randombytes.h alloc.h remoteip.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper.c

main_tlswrapper_loadpem.o: main_tlswrapper_loadpem.c randombytes.h log.h \
 alloc.h tls.h fsyncfile.h writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_loadpem.c

main_tlswrapper_tcpproxy.o: main_tlswrapper_tcpproxy.c randombytes.h \
 resolvehost.h portparse.h socket.h e.h log.h conn.h tls.h jail.h \
 randommod.h nanoseconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_tcpproxy.c

nanoseconds.o: nanoseconds.c nanoseconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c nanoseconds.c

pipe.o: pipe.c e.h log.h readall.h writeall.h alloc.h pipe.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pipe.c

portparse.o: portparse.c portparse.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c portparse.c

randombytes.o: randombytes.c log.h randombytes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randombytes.c

randommod.o: randommod.c randombytes.h randommod.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randommod.c

readall.o: readall.c e.h readall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c readall.c

remoteip.o: remoteip.c remoteip.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c remoteip.c

resolvehost.o: resolvehost.c e.h blocking.h log.h jail.h randommod.h \
 resolvehost.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c resolvehost.c

socket.o: socket.c blocking.h e.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket.c

testalloc.o: testalloc.c alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c testalloc.c

testchacha20.o: testchacha20.c log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c testchacha20.c

testjail.o: testjail.c log.h jail.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c testjail.c

testrandombytes.o: testrandombytes.c log.h randombytes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c testrandombytes.c

tls_anchor.o: tls_anchor.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_anchor.c

tls_certfile.o: tls_certfile.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_certfile.c

tls_cipher.o: tls_cipher.c tls.h
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

tls_keyjail.o: tls_keyjail.c pipe.h randombytes.h log.h jail.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keyjail.c

tls_keytype.o: tls_keytype.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keytype.c

tls_pem.o: tls_pem.c alloc.h readall.h randombytes.h log.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pem.c

tls_pipe.o: tls_pipe.c tls.h pipe.h randombytes.h alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pipe.c

tls_profile.o: tls_profile.c log.h randombytes.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_profile.c

tls_pubcrt.o: tls_pubcrt.c alloc.h log.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pubcrt.c

tls_seccrt.o: tls_seccrt.c log.h tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_seccrt.c

tls_timeout.o: tls_timeout.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_timeout.c

tls_version.o: tls_version.c tls.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_version.c

tlswrapper.o: tlswrapper.c main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tlswrapper.c

writeall.o: writeall.c e.h jail.h writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c writeall.c

OBJECTS+=alloc.o
OBJECTS+=blocking.o
OBJECTS+=conn.o
OBJECTS+=crypto_scalarmult_curve25519.o
OBJECTS+=e.o
OBJECTS+=fsyncfile.o
OBJECTS+=jail.o
OBJECTS+=jail_poll.o
OBJECTS+=log.o
OBJECTS+=main_tlswrapper.o
OBJECTS+=main_tlswrapper_loadpem.o
OBJECTS+=main_tlswrapper_tcpproxy.o
OBJECTS+=nanoseconds.o
OBJECTS+=pipe.o
OBJECTS+=portparse.o
OBJECTS+=randombytes.o
OBJECTS+=randommod.o
OBJECTS+=readall.o
OBJECTS+=remoteip.o
OBJECTS+=resolvehost.o
OBJECTS+=socket.o
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

testalloc: testalloc.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testalloc testalloc.o $(OBJECTS) $(LDFLAGS)

testchacha20: testchacha20.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testchacha20 testchacha20.o $(OBJECTS) $(LDFLAGS)

testjail: testjail.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testjail testjail.o $(OBJECTS) $(LDFLAGS)

testrandombytes: testrandombytes.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testrandombytes testrandombytes.o $(OBJECTS) $(LDFLAGS)

tlswrapper: tlswrapper.o $(OBJECTS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o tlswrapper tlswrapper.o $(OBJECTS) $(LDFLAGS)


test: $(BINARIES)
	./test.sh

clean:
	rm -f *.o $(BINARIES)

