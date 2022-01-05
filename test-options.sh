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
( tlswrappernojail -Q -d testfifo </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects fifo as a certfile'
( tlswrappernojail -Q -f testfifo </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects fifo as a anchorfile'
( tlswrappernojail -Q -a testfifo </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects nonexistent file as a certdir'
( tlswrappernojail -Q -d notexist </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects nonexistent file as a certfile'
( tlswrappernojail -Q -f notexist </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects nonexistent file as a anchorfile'
( tlswrappernojail -Q -a notexist </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects regular file as a certdir'
( tlswrappernojail -Q -d testfile </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects directory as a certfile'
( tlswrappernojail -Q -f testdir </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects directory as a anchor file'
( tlswrappernojail -Q -a testdir </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects link to regular file as a certdir'
( tlswrappernojail -Q -d testfilelink </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects link to directory as a certfile'
( tlswrappernojail -Q -f testdirlink </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects link to directory as a anchorfile'
( tlswrappernojail -Q -a testdirlink </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo

# TLS version
echo 'tlswrapper rejects bad min TLS version'
( tlswrappernojail -Q -f testfile -m xxx </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects bad max TLS version'
( tlswrappernojail -Q -f testfile -M xxx </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo

# ciphers
echo 'tlswrapper rejects bad ciphername'
( tlswrappernojail -Q -f testfile -c xxx </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo

# ephemeral 
echo 'tlswrapper rejects bad ephemeral name'
( tlswrappernojail -Q -f testfile -e xxx </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo

# proxy protocol
echo 'tlswrapper rejects bad proxy protocol version'
( tlswrappernojail -Q -f testfile -P 9 </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo

# user from client cert. 
echo 'tlswrapper rejects bad ASN.1 object'
( tlswrappernojail -Q -f testfile -U xxx </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo

# timeouts
echo 'tlswrapper rejects zero number as a network timeout'
( tlswrappernojail -Q -f testfile -t0 true </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects negative number as a network timeout'
( tlswrappernojail -Q -f testfile -t -1 true </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects nefative number as a handshake timeout'
echo 'tlswrapper rejects bad number as a network timeout'
( tlswrappernojail -Q -f testfile -t badtimeout true </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
echo 'tlswrapper rejects bad number as a handshake timeout'
echo 'tlswrapper rejects too large number as a network timeout'
( tlswrappernojail -Q -f testfile -t 86401 true </dev/null 2>&1; echo $?;) | sed 's/ (.*)/ /'
echo
