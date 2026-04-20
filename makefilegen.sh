#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "EMPTYDIR?=/var/lib/tlswrapper/empty"
    echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -DEMPTYDIR=\\\"\$(EMPTYDIR)\\\""
    echo "LDFLAGS+=-lbearssl"
    echo "CPPFLAGS?="
    echo
    echo "DESTDIR?="
    echo "PREFIX?=/usr/local"
    echo
    echo "INSTALL?=install"
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
        gcc -isystem /usr/local/include -MM "${file}"
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

    echo "libs: trylibs.sh"
    echo "	env CC=\"\$(CC)\" ./trylibs.sh -lsocket -lnsl -lrandombytes -l25519 >libs 2>libs.log"
    echo "	cat libs"
    echo

    echo "tlswrapper-tcp: tlswrapper"
    echo "	ln -sf tlswrapper tlswrapper-tcp"
    echo

    echo "tlswrapper-smtp: tlswrapper"
    echo "	ln -sf tlswrapper tlswrapper-smtp"
    echo

    echo "install: \$(BINARIES) tlswrapper-tcp tlswrapper-smtp"
    echo "	mkdir -p \$(DESTDIR)\$(PREFIX)/bin"
    echo "	mkdir -p \$(DESTDIR)\$(PREFIX)/share/man/man1"
    echo "	mkdir -p \$(DESTDIR)\$(EMPTYDIR)"
    echo "	\$(INSTALL) -m 0755 tlswrapper \$(DESTDIR)\$(PREFIX)/bin/tlswrapper"
    echo "	\$(INSTALL) -m 0755 tlswrapper-tcp \$(DESTDIR)\$(PREFIX)/bin/tlswrapper-tcp"
    echo "	\$(INSTALL) -m 0755 tlswrapper-smtp \$(DESTDIR)\$(PREFIX)/bin/tlswrapper-smtp"
    echo "	\$(INSTALL) -m 0644 man/tlswrapper.1 \$(DESTDIR)\$(PREFIX)/share/man/man1/tlswrapper.1"
    echo "	\$(INSTALL) -m 0644 man/tlswrapper-smtp.1 \$(DESTDIR)\$(PREFIX)/share/man/man1/tlswrapper-smtp.1"
    echo "	\$(INSTALL) -m 0644 man/tlswrapper-tcp.1 \$(DESTDIR)\$(PREFIX)/share/man/man1/tlswrapper-tcp.1"
    echo

    echo "test: \$(BINARIES) tlswrapper-tcp tlswrapper-smtp"
    echo "	\$(MAKE) test -C tests"
    echo
    echo "pythontest: \$(BINARIES) tlswrapper-tcp tlswrapper-smtp"
    echo "	\$(MAKE) pythontest -C tests"
    echo

    echo "clean:"
    echo "	\$(MAKE) clean -C tests"
    echo "	rm -f *.log *.o \$(BINARIES) libs tlswrapper-tcp tlswrapper-smtp has*.h"
    echo 

  ) > Makefile
)
