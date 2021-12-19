#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -pedantic -I./bearssl/inc"
    echo "LDFLAGS+=-L./bearssl/build -lbearssl"
    echo "DESTDIR?="
    echo "EMPTYDIR?=/var/lib/tlswrapper/empty"
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

    echo "all: bearssl \$(BINARIES)"
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

    echo "install: tlswrapper tlswrapper-tcp"
    echo "	install -D -m 0755 tlswrapper \$(DESTDIR)/usr/bin/tlswrapper"
    echo "	install -D -m 0755 tlswrapper-tcp \$(DESTDIR)/usr/bin/tlswrapper-tcp"
    echo "	install -d -m 0755 \$(DESTDIR)/\$(EMPTYDIR)"
    echo

    echo "test: bearssl \$(BINARIES)"
    echo "	./test.sh"
    echo

    echo "clean:"
    echo "	rm -f *.o \$(BINARIES) tlswrapper-tcp"
    echo 

  ) > Makefile
)
