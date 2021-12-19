#!/bin/sh

cleanup() {
  ex=$?
  rm -rf tlswrappernojail testfifo testfile testdir .dottestdir .dottestfile testdirlink testfilelink
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

PATH="./:${PATH}"
export PATH

ln -s tlswrapper-test tlswrappernojail
mkfifo testfifo
mkdir .dottestdir testdir
touch .dottestfile testfile
ln -s testdir testdirlink
ln -s testfile testfilelink

# certs
echo 'tlswrapper rejects fifo as a certdir'
(tlswrapper-test -qr tlswrappernojail -d `pwd`/testfifo 2>&1; echo $?;) | sed 's,/.*/,/.../,'
echo
echo 'tlswrapper rejects fifo as a certfile'
tlswrapper-test -qr tlswrappernojail -f testfifo 2>&1
echo $?; echo
echo 'tlswrapper rejects fifo as a anchorfile'
tlswrapper-test -qr tlswrappernojail -a testfifo 2>&1
echo $?; echo
echo 'tlswrapper rejects nonexistent file as a certdir'
(tlswrapper-test -qr tlswrappernojail -d `pwd`/notexist 2>&1; echo $?;) | sed 's,/.*/,/.../,'
echo
echo 'tlswrapper rejects nonexistent file as a certfile'
tlswrapper-test -qr tlswrappernojail -f notexist 2>&1
echo $?; echo
echo 'tlswrapper rejects nonexistent file as a anchorfile'
tlswrapper-test -qr tlswrappernojail -a notexist 2>&1
echo $?; echo
echo 'tlswrapper rejects regular file as a certdir'
(tlswrapper-test -qr tlswrappernojail -d `pwd`/testfile 2>&1; echo $?;) | sed 's,/.*/,/.../,'
echo
echo 'tlswrapper rejects directory as a certfile'
tlswrapper-test -qr tlswrappernojail -f testdir 2>&1
echo $?; echo
echo 'tlswrapper rejects directory as a anchor file'
tlswrapper-test -qr tlswrappernojail -a testdir 2>&1
echo $?; echo
echo 'tlswrapper rejects link to regular file as a certdir'
tlswrapper-test -qr tlswrappernojail -d testfilelink 2>&1
echo $?; echo
echo 'tlswrapper rejects link to directory as a certfile'
tlswrapper-test -qr tlswrappernojail -f testdirlink 2>&1
echo $?; echo
echo 'tlswrapper rejects link to directory as a anchorfile'
tlswrapper-test -qr tlswrappernojail -a testdirlink 2>&1
echo $?; echo
echo 'tlswrapper rejects relative directory as a certdir'
tlswrapper-test -qr tlswrappernojail -d testdir 2>&1
echo $?; echo

# TLS version
echo 'tlswrapper rejects bad min TLS version'
tlswrapper-test -qr tlswrappernojail -f testfile -m xxx 2>&1
echo $?; echo
echo 'tlswrapper rejects bad max TLS version'
tlswrapper-test -qr tlswrappernojail -f testfile -M xxx 2>&1
echo $?; echo

# ciphers
echo 'tlswrapper rejects bad ciphername'
tlswrapper-test -qr tlswrappernojail -f testfile -c xxx 2>&1
echo $?; echo

# ephemeral 
echo 'tlswrapper rejects bad ephemeral name'
tlswrapper-test -qr tlswrappernojail -f testfile -e xxx 2>&1
echo $?; echo

# proxy protocol
echo 'tlswrapper rejects bad proxy protocol version'
tlswrapper-test -qr tlswrappernojail -f testfile -p 9 2>&1
echo $?; echo

# user from client cert. 
echo 'tlswrapper rejects bad ASN.1 object'
tlswrapper-test -qr tlswrappernojail -f testfile -U xxx 2>&1
echo $?; echo

# timeouts
echo 'tlswrapper rejects zero number as a network timeout'
tlswrapper-test -qr tlswrappernojail -f testfile -t0 true 2>&1
echo $?; echo
echo 'tlswrapper rejects zero number as a handshake timeout'
tlswrapper-test -qr tlswrappernojail -f testfile -T0 true 2>&1
echo $?; echo
echo 'tlswrapper rejects negative number as a network timeout'
tlswrapper-test -qr tlswrappernojail -f testfile -t -1 true 2>&1
echo $?; echo
echo 'tlswrapper rejects nefative number as a handshake timeout'
tlswrapper-test -qr tlswrappernojail -f testfile -T -1 true 2>&1
echo $?; echo
echo 'tlswrapper rejects bad number as a network timeout'
tlswrapper-test -qr tlswrappernojail -f testfile -t badtimeout true 2>&1
echo $?; echo
echo 'tlswrapper rejects bad numbern as a handshake timeout'
tlswrapper-test -qr tlswrappernojail -f testfile -T badtimeout true 2>&1
echo $?; echo
echo 'tlswrapper rejects too large number as a network timeout'
tlswrapper-test -qr tlswrappernojail -f testfile -t 86401 true 2>&1
echo $?; echo
echo 'tlswrapper rejects too large numbern as a handshake timeout'
tlswrapper-test -qr tlswrappernojail -f testfile -T 86401 true 2>&1
echo $?; echo

