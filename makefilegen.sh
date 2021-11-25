#!/bin/sh

(
  (
    echo "CC?=cc"
    echo "CFLAGS+=-W -Wall -Os -fPIC -fwrapv -I./bearssl/inc"
    echo "LDFLAGS+=-L./bearssl/build -lbearssl"
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
    echo "	\$(CC) -o try.o -lbearssl try.c || (sh bearssl.sh; cd bearssl; make; rm build/*.so; )"
    echo "	rm -f try.o try.c"
    echo

    echo "test: bearssl \$(BINARIES)"
    echo "	./test.sh"
    echo

    echo "clean:"
    echo "	rm -f *.o \$(BINARIES)"
    echo 

  ) > Makefile
)
