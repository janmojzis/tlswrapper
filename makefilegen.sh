#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "EMPTYDIR?=/var/lib/tlswrapper/empty"
    echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -DEMPTYDIR=\\\"\$(EMPTYDIR)\\\""
    echo "LDFLAGS+=-lbearssl"
    echo "DESTDIR?="
    echo 

    # binaries
    i=0
    for file in `ls *.c`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        if [ $i -eq 0 ]; then
          echo "BINARIES=${x}"
        else
          echo "BINARIES+=${x}"
        fi
        i=`expr $i + 1`
      fi
    done
    echo

    echo "all: \$(BINARIES) tlswrapper-tcp tlswrapper-smtp"
    echo 

    touch haslib25519.h haslibrandombytes.h
    for file in `ls *.c`; do
      (
        gcc -MM "${file}"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -c ${file}"
        echo
      )
    done
    rm haslib25519.h

    i=0
    for file in `ls *.c`; do
      if ! grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$/.o/'`
        if [ $i -eq 0 ]; then
          echo "OBJECTS=${x}"
        else
          echo "OBJECTS+=${x}"
        fi
        i=`expr $i + 1`
      fi
    done
    echo

    for file in `ls *.c`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        echo "${x}: ${x}.o \$(OBJECTS) lib25519.lib librandombytes.lib"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -o ${x} ${x}.o \$(OBJECTS) \$(LDFLAGS) \`cat lib25519.lib\` \`cat librandombytes.lib\`"
        echo 
      fi
    done
    echo

    echo "haslib25519.h: trylib25519.sh"
    echo "	env CC=\$(CC) ./trylib25519.sh && echo '#define HASLIB25519 1' > haslib25519.h || true > haslib25519.h"
    echo

    echo "haslibrandombytes.h: trylibrandombytes.sh"
    echo "	env CC=\$(CC) ./trylibrandombytes.sh && echo '#define HASLIBRANDOMBYTES 1' > haslibrandombytes.h || true > haslibrandombytes.h"

    echo "lib25519.lib: trylib25519.sh"
    echo "	env CC=\$(CC) ./trylib25519.sh && echo '-l25519' > lib25519.lib || true > lib25519.lib"
    echo

    echo "librandombytes.lib: trylibrandombytes.sh"
    echo "	env CC=\$(CC) ./trylibrandombytes.sh && echo '-lrandombytes' > librandombytes.lib || true > librandombytes.lib"
    echo

    echo "tlswrapper-tcp: tlswrapper"
    echo "	ln -s tlswrapper tlswrapper-tcp"
    echo

    echo "tlswrapper-smtp: tlswrapper"
    echo "	ln -s tlswrapper tlswrapper-smtp"
    echo

    echo "install: \$(BINARIES) tlswrapper-tcp"
    echo "	install -D -m 0755 tlswrapper \$(DESTDIR)/usr/bin/tlswrapper"
    echo "	install -D -m 0755 tlswrapper-tcp \$(DESTDIR)/usr/bin/tlswrapper-tcp"
    echo "	install -D -m 0755 tlswrapper-smtp \$(DESTDIR)/usr/bin/tlswrapper-smtp"
    echo "	install -d -m 0755 \$(DESTDIR)/\$(EMPTYDIR)"
    echo

    echo "test: \$(BINARIES) tlswrapper-tcp"
    echo "	sh runtest.sh test-cipher.sh test-cipher.out test-cipher.exp"
    echo "	sh runtest.sh test-ephemeral.sh test-ephemeral.out test-ephemeral.exp"
    echo "	sh runtest.sh test-options.sh test-options.out test-options.exp"
    echo "	sh runtest.sh test-pp.sh test-pp.out test-pp.exp"
    echo "	sh runtest.sh test-badcert.sh test-badcert.out test-badcert.exp"
    echo "	sh runtest.sh test-badkey.sh test-badkey.out test-badkey.exp"
    echo "	sh runtest.sh test-childexit.sh test-childexit.out test-childexit.exp"
    echo "	sh runtest.sh test-okcert.sh test-okcert.out test-okcert.exp"
    echo

    echo "clean:"
    echo "	rm -f *.o *.out \$(BINARIES) tlswrapper-tcp tlswrapper-smtp haslib25519.h lib25519.lib haslibrandombytes.h librandombytes.lib"
    echo 

  ) > Makefile
)
