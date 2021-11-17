#!/bin/sh

(
  (
    echo "CC=gcc"
    echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -Wall" -I/usr/include/bearssl
    #echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -Wall"
    echo "LDFLAGS+=-lbearssl"
    echo 

    binaries=""
    objects=""
    for file in `ls *.c`; do
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        binaries="${binaries} ${x}"
      else
        x=`echo "${file}" | sed 's/\.c$/.o/'`
        objects="${objects} ${x}"
      fi
    done

    echo "all: ${binaries}"
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
      if grep '^int main(' "${file}" >/dev/null; then
        x=`echo "${file}" | sed 's/\.c$//'`
        echo "${x}: ${x}.o ${objects}"
        echo "	\$(CC) \$(CFLAGS) \$(CPPFLAGS) -o ${x} ${x}.o ${objects} \$(LDFLAGS)"
        echo 
      fi
    done

    echo "test: ${binaries}"
    echo "	./test.sh"
    echo

    echo "clean:"
    echo "	rm -f *.o ${binaries}"
    echo 

  ) > Makefile
)
