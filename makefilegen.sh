#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "EMPTYDIR?=/var/lib/tlswrapper/empty"
    echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -I./bearssl/inc -DEMPTYDIR=\\\"\$(EMPTYDIR)\\\""
    echo "LDFLAGS+=-L./bearssl/build -lbearssl"
    echo "DESTDIR?="
    echo 

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

    echo "all: bearssl \$(BINARIES) tlswrapper-tcp"
    echo 

    for file in `ls *.c`; do
      (
        #gcc -I/usr/include/bearssl -MM "${file}"
        gcc -MM "${file}"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -c ${file}"
        echo
      )
    done

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
        echo "${x}: ${x}.o \$(OBJECTS)"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -o ${x} ${x}.o \$(OBJECTS) \$(LDFLAGS)"
        echo 
      fi
    done
    echo

    echo "bearssl:"
    echo "	echo 'int main(){}' > try.c"
    echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -o try.o \$(LDFLAGS) try.c || (sh bearssl.sh; cd bearssl; make; rm build/*.so; )"
    echo "	rm -f try.o try.c"
    echo "	mkdir -p bearssl/inc"
    echo

    echo "tlswrapper-tcp: tlswrapper"
    echo "	ln -s tlswrapper tlswrapper-tcp"
    echo

    echo "install: \$(BINARIES) tlswrapper-tcp"
    echo "	install -D -m 0755 tlswrapper \$(DESTDIR)/usr/bin/tlswrapper"
    echo "	install -D -m 0755 tlswrapper-tcp \$(DESTDIR)/usr/bin/tlswrapper-tcp"
    echo "	install -d -m 0755 \$(DESTDIR)/\$(EMPTYDIR)"
    echo

    echo "test: bearssl \$(BINARIES) tlswrapper-tcp"
    echo "	sh test-options.sh > test-options.out; cmp test-options.exp test-options.out || (cat test-options.out; exit 1;)"
    echo "	sh test-proxyprotocol.sh > test-proxyprotocol.out; cmp test-proxyprotocol.exp test-proxyprotocol.out || (cat test-proxyprotocol.out; exit 1;)"
    echo "	sh test-badcert.sh > test-badcert.out; cmp test-badcert.exp test-badcert.out || (cat test-badcert.out; exit 1;)"
    echo "	sh test-badkey.sh > test-badkey.out; cmp test-badkey.exp test-badkey.out || (cat test-badkey.out; exit 1;)"
    echo "	sh test-okcert.sh > test-okcert.out; cmp test-okcert.exp test-okcert.out || (cat test-okcert.out; exit 1;)"
    echo

    echo "clean:"
    echo "	rm -f *.o *.out \$(BINARIES) tlswrapper-tcp"
    echo 

  ) > Makefile
)
