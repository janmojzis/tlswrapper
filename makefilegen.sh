#!/bin/sh

(
  (
    echo "CC=gcc"
    echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -Wall" -I./bearssl/inc -I/usr/include/bearssl
    #echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -Wall"
    echo "LDFLAGS+=-L./bearssl/build -lbearssl"
    echo 

    for file in `ls *.c`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        echo "BINARIES+=${x}"
      fi
    done
    echo

    echo "all: \$(BINARIES)"
    echo 

    for file in `ls *.c`; do
      (
        #gcc -I/usr/include/bearssl -MM "${file}"
        gcc -MM "${file}"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -c ${file}"
        echo
      )
    done

    for file in `ls *.c`; do
      if ! grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$/.o/'`
        echo "OBJECTS+=${x}"
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

    echo "test: \$(BINARIES)"
    echo "	./test.sh"
    echo

    echo "clean:"
    echo "	rm -f *.o \$(BINARIES)"
    echo 

  ) > Makefile
)
