CC=gcc
CFLAGS+=-W -Wall -Os -fPIC -fwrapv -Wall -I/usr/include/bearssl
LDFLAGS+=-lbearssl

all:  testalloc testchacha20 testjail testrandombytes testresolvehost tlswrapper

alloc.o: alloc.c randombytes.h alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c alloc.c

blocking.o: blocking.c blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c blocking.c

conn.o: conn.c socket.h nanoseconds.h e.h log.h conn.h
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
 randombytes.h alloc.h remoteip.h tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper.c

main_tlswrapper_loadpem.o: main_tlswrapper_loadpem.c randombytes.h log.h \
 alloc.h tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h \
 fsyncfile.h writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_loadpem.c

main_tlswrapper_tcpproxy.o: main_tlswrapper_tcpproxy.c randombytes.h \
 resolvehost.h portparse.h socket.h e.h log.h conn.h tls.h \
 /usr/include/bearssl/bearssl.h /usr/include/bearssl/bearssl_hash.h \
 /usr/include/bearssl/bearssl_hmac.h /usr/include/bearssl/bearssl_kdf.h \
 /usr/include/bearssl/bearssl_rand.h /usr/include/bearssl/bearssl_block.h \
 /usr/include/bearssl/bearssl_prf.h /usr/include/bearssl/bearssl_aead.h \
 /usr/include/bearssl/bearssl_rsa.h /usr/include/bearssl/bearssl_ec.h \
 /usr/include/bearssl/bearssl_ssl.h /usr/include/bearssl/bearssl_x509.h \
 /usr/include/bearssl/bearssl_pem.h jail.h randommod.h nanoseconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main_tlswrapper_tcpproxy.c

nanoseconds.o: nanoseconds.c nanoseconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c nanoseconds.c

pipe.o: pipe.c e.h log.h readall.h writeall.h alloc.h pipe.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c pipe.c

portparse.o: portparse.c portparse.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c portparse.c

randombytes.o: randombytes.c log.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h \
 randombytes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randombytes.c

randommod.o: randommod.c randombytes.h randommod.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randommod.c

readall.o: readall.c e.h readall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c readall.c

remoteip.o: remoteip.c remoteip.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c remoteip.c

resolvehost.o: resolvehost.c e.h log.h jail.h randommod.h resolvehost.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c resolvehost.c

socket.o: socket.c blocking.h e.h socket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c socket.c

testalloc.o: testalloc.c alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c testalloc.c

testchacha20.o: testchacha20.c log.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c testchacha20.c

testjail.o: testjail.c log.h jail.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c testjail.c

testrandombytes.o: testrandombytes.c log.h randombytes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c testrandombytes.c

testresolvehost.o: testresolvehost.c resolvehost.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c testresolvehost.c

tls_anchor.o: tls_anchor.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_anchor.c

tls_certfile.o: tls_certfile.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_certfile.c

tls_cipher.o: tls_cipher.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_cipher.c

tls_crypto_scalarmult.o: tls_crypto_scalarmult.c tls.h \
 /usr/include/bearssl/bearssl.h /usr/include/bearssl/bearssl_hash.h \
 /usr/include/bearssl/bearssl_hmac.h /usr/include/bearssl/bearssl_kdf.h \
 /usr/include/bearssl/bearssl_rand.h /usr/include/bearssl/bearssl_block.h \
 /usr/include/bearssl/bearssl_prf.h /usr/include/bearssl/bearssl_aead.h \
 /usr/include/bearssl/bearssl_rsa.h /usr/include/bearssl/bearssl_ec.h \
 /usr/include/bearssl/bearssl_ssl.h /usr/include/bearssl/bearssl_x509.h \
 /usr/include/bearssl/bearssl_pem.h crypto_scalarmult_curve25519.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_crypto_scalarmult.c

tls_ecdhe.o: tls_ecdhe.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_ecdhe.c

tls_ecdsa.o: tls_ecdsa.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_ecdsa.c

tls_error.o: tls_error.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_error.c

tls_keyjail.o: tls_keyjail.c pipe.h randombytes.h log.h jail.h tls.h \
 /usr/include/bearssl/bearssl.h /usr/include/bearssl/bearssl_hash.h \
 /usr/include/bearssl/bearssl_hmac.h /usr/include/bearssl/bearssl_kdf.h \
 /usr/include/bearssl/bearssl_rand.h /usr/include/bearssl/bearssl_block.h \
 /usr/include/bearssl/bearssl_prf.h /usr/include/bearssl/bearssl_aead.h \
 /usr/include/bearssl/bearssl_rsa.h /usr/include/bearssl/bearssl_ec.h \
 /usr/include/bearssl/bearssl_ssl.h /usr/include/bearssl/bearssl_x509.h \
 /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keyjail.c

tls_keytype.o: tls_keytype.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_keytype.c

tls_pem.o: tls_pem.c alloc.h readall.h randombytes.h log.h tls.h \
 /usr/include/bearssl/bearssl.h /usr/include/bearssl/bearssl_hash.h \
 /usr/include/bearssl/bearssl_hmac.h /usr/include/bearssl/bearssl_kdf.h \
 /usr/include/bearssl/bearssl_rand.h /usr/include/bearssl/bearssl_block.h \
 /usr/include/bearssl/bearssl_prf.h /usr/include/bearssl/bearssl_aead.h \
 /usr/include/bearssl/bearssl_rsa.h /usr/include/bearssl/bearssl_ec.h \
 /usr/include/bearssl/bearssl_ssl.h /usr/include/bearssl/bearssl_x509.h \
 /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pem.c

tls_pipe.o: tls_pipe.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h \
 pipe.h randombytes.h alloc.h log.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pipe.c

tls_profile.o: tls_profile.c log.h randombytes.h tls.h \
 /usr/include/bearssl/bearssl.h /usr/include/bearssl/bearssl_hash.h \
 /usr/include/bearssl/bearssl_hmac.h /usr/include/bearssl/bearssl_kdf.h \
 /usr/include/bearssl/bearssl_rand.h /usr/include/bearssl/bearssl_block.h \
 /usr/include/bearssl/bearssl_prf.h /usr/include/bearssl/bearssl_aead.h \
 /usr/include/bearssl/bearssl_rsa.h /usr/include/bearssl/bearssl_ec.h \
 /usr/include/bearssl/bearssl_ssl.h /usr/include/bearssl/bearssl_x509.h \
 /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_profile.c

tls_pubcrt.o: tls_pubcrt.c alloc.h log.h tls.h \
 /usr/include/bearssl/bearssl.h /usr/include/bearssl/bearssl_hash.h \
 /usr/include/bearssl/bearssl_hmac.h /usr/include/bearssl/bearssl_kdf.h \
 /usr/include/bearssl/bearssl_rand.h /usr/include/bearssl/bearssl_block.h \
 /usr/include/bearssl/bearssl_prf.h /usr/include/bearssl/bearssl_aead.h \
 /usr/include/bearssl/bearssl_rsa.h /usr/include/bearssl/bearssl_ec.h \
 /usr/include/bearssl/bearssl_ssl.h /usr/include/bearssl/bearssl_x509.h \
 /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_pubcrt.c

tls_seccrt.o: tls_seccrt.c log.h tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_seccrt.c

tls_timeout.o: tls_timeout.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_timeout.c

tls_version.o: tls_version.c tls.h /usr/include/bearssl/bearssl.h \
 /usr/include/bearssl/bearssl_hash.h /usr/include/bearssl/bearssl_hmac.h \
 /usr/include/bearssl/bearssl_kdf.h /usr/include/bearssl/bearssl_rand.h \
 /usr/include/bearssl/bearssl_block.h /usr/include/bearssl/bearssl_prf.h \
 /usr/include/bearssl/bearssl_aead.h /usr/include/bearssl/bearssl_rsa.h \
 /usr/include/bearssl/bearssl_ec.h /usr/include/bearssl/bearssl_ssl.h \
 /usr/include/bearssl/bearssl_x509.h /usr/include/bearssl/bearssl_pem.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tls_version.c

tlswrapper.o: tlswrapper.c main.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c tlswrapper.c

writeall.o: writeall.c writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c writeall.c

testalloc: testalloc.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testalloc testalloc.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o $(LDFLAGS)

testchacha20: testchacha20.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testchacha20 testchacha20.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o $(LDFLAGS)

testjail: testjail.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testjail testjail.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o $(LDFLAGS)

testrandombytes: testrandombytes.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testrandombytes testrandombytes.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o $(LDFLAGS)

testresolvehost: testresolvehost.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o testresolvehost testresolvehost.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o $(LDFLAGS)

tlswrapper: tlswrapper.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o tlswrapper tlswrapper.o  alloc.o blocking.o conn.o crypto_scalarmult_curve25519.o e.o fsyncfile.o jail.o jail_poll.o log.o main_tlswrapper.o main_tlswrapper_loadpem.o main_tlswrapper_tcpproxy.o nanoseconds.o pipe.o portparse.o randombytes.o randommod.o readall.o remoteip.o resolvehost.o socket.o tls_anchor.o tls_certfile.o tls_cipher.o tls_crypto_scalarmult.o tls_ecdhe.o tls_ecdsa.o tls_error.o tls_keyjail.o tls_keytype.o tls_pem.o tls_pipe.o tls_profile.o tls_pubcrt.o tls_seccrt.o tls_timeout.o tls_version.o writeall.o $(LDFLAGS)

test:  testalloc testchacha20 testjail testrandombytes testresolvehost tlswrapper
	./test.sh

clean:
	rm -f *.o  testalloc testchacha20 testjail testrandombytes testresolvehost tlswrapper

