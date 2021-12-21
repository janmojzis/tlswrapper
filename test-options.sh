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
tlswrappernojail -q -d testfifo </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects fifo as a certfile'
tlswrappernojail -q -f testfifo </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects fifo as a anchorfile'
tlswrappernojail -q -a testfifo </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects nonexistent file as a certdir'
tlswrappernojail -q -d notexist </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects nonexistent file as a certfile'
tlswrappernojail -q -f notexist </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects nonexistent file as a anchorfile'
tlswrappernojail -q -a notexist </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects regular file as a certdir'
tlswrappernojail -q -d testfile </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects directory as a certfile'
tlswrappernojail -q -f testdir </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects directory as a anchor file'
tlswrappernojail -q -a testdir </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects link to regular file as a certdir'
tlswrappernojail -q -d testfilelink </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects link to directory as a certfile'
tlswrappernojail -q -f testdirlink </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects link to directory as a anchorfile'
tlswrappernojail -q -a testdirlink </dev/null 2>&1
echo $?; echo

# TLS version
echo 'tlswrapper rejects bad min TLS version'
tlswrappernojail -q -f testfile -m xxx </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects bad max TLS version'
tlswrappernojail -q -f testfile -M xxx </dev/null 2>&1
echo $?; echo

# ciphers
echo 'tlswrapper rejects bad ciphername'
tlswrappernojail -q -f testfile -c xxx </dev/null 2>&1
echo $?; echo

# ephemeral 
echo 'tlswrapper rejects bad ephemeral name'
tlswrappernojail -q -f testfile -e xxx </dev/null 2>&1
echo $?; echo

# proxy protocol
echo 'tlswrapper rejects bad proxy protocol version'
tlswrappernojail -q -f testfile -P 9 </dev/null 2>&1
echo $?; echo

# user from client cert. 
echo 'tlswrapper rejects bad ASN.1 object'
tlswrappernojail -q -f testfile -U xxx </dev/null 2>&1
echo $?; echo

# timeouts
echo 'tlswrapper rejects zero number as a network timeout'
tlswrappernojail -q -f testfile -t0 true </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects zero number as a handshake timeout'
tlswrappernojail -q -f testfile -T0 true </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects negative number as a network timeout'
tlswrappernojail -q -f testfile -t -1 true </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects nefative number as a handshake timeout'
tlswrappernojail -q -f testfile -T -1 true </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects bad number as a network timeout'
tlswrappernojail -q -f testfile -t badtimeout true </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects bad numbern as a handshake timeout'
tlswrappernojail -q -f testfile -T badtimeout true </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects too large number as a network timeout'
tlswrappernojail -q -f testfile -t 86401 true </dev/null 2>&1
echo $?; echo
echo 'tlswrapper rejects too large numbern as a handshake timeout'
tlswrappernojail -q -f testfile -T 86401 true </dev/null 2>&1
echo $?; echo
