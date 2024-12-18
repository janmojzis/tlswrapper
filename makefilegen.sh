#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "EMPTYDIR?=/var/lib/tlswrapper/empty"
    echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -DEMPTYDIR=\\\"\$(EMPTYDIR)\\\""
    echo "LDFLAGS+=-lbearssl"
    echo "CPPFLAGS?="
    echo "DESTDIR?="
    echo 

    # binaries
    i=0
    for file in `ls -1 *.c | grep -v '^has'`; do
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

    for file in `ls -1 has*.c`; do
      hfile=`echo ${file} | sed 's/\.c/.h/'`
      touch "${hfile}"
    done
    for file in `ls -1 *.c | grep -v '^has'`; do
      (
        gcc -MM "${file}"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -c ${file}"
        echo
      )
    done
    rm has*.h

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

    for file in `ls *.c | grep -v '^has'`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        echo "${x}: ${x}.o \$(OBJECTS) libs"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -o ${x} ${x}.o \$(OBJECTS) \$(LDFLAGS) \`cat libs\`"
        echo 
      fi
    done
    echo

    for cfile in `ls -1 has*.c`; do
      hfile=`echo ${cfile} | sed 's/\.c/.h/'`
      touch "${hfile}"
      echo "${hfile}: tryfeature.sh ${cfile} libs"
      echo "	env CC=\"\$(CC)\" CFLAGS=\"\$(CFLAGS)\" LDFLAGS=\"\$(LDFLAGS) \`cat libs\`\" ./tryfeature.sh ${cfile} > ${hfile}"
      echo "	cat ${hfile}"
      echo
    done

    echo "libs: trylib.sh"
    echo "	rm -f libs"
    echo "	env CC=\"\$(CC)\" ./trylib.sh -lsocket -lnsl >>libs"
    echo "	env CC=\"\$(CC)\" ./trylib.sh -lrandombytes >>libs"
    echo "	env CC=\"\$(CC)\" ./trylib.sh -l25519 >>libs"
    echo "	cat libs"
    echo

    echo "tlswrapper-tcp: tlswrapper"
    echo "	ln -s tlswrapper tlswrapper-tcp"
    echo

    echo "tlswrapper-smtp: tlswrapper"
    echo "	ln -s tlswrapper tlswrapper-smtp"
    echo

    echo "install: \$(BINARIES) tlswrapper-tcp tlswrapper-smtp"
    echo "	install -D -m 0755 tlswrapper \$(DESTDIR)/usr/bin/tlswrapper"
    echo "	install -D -m 0755 tlswrapper-tcp \$(DESTDIR)/usr/bin/tlswrapper-tcp"
    echo "	install -D -m 0755 tlswrapper-smtp \$(DESTDIR)/usr/bin/tlswrapper-smtp"
    echo "	install -d -m 0755 \$(DESTDIR)/\$(EMPTYDIR)"
    echo

    echo "test: \$(BINARIES) tlswrapper-tcp tlswrapper-smtp"
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
    echo "	rm -f *.o *.out \$(BINARIES) libs tlswrapper-tcp tlswrapper-smtp has*.h"
    echo 

  ) > Makefile
)
