#!/bin/sh

TCPREMOTEIP=0.0.0.0; export TCPREMOTEIP
TCPREMOTEPORT=0; export TCPREMOTEPORT
TCPLOCALIP=0.0.0.0; export TCPLOCALIP
TCPLOCALPORT=0; export TCPLOCALPORT

cleanup() {
  ex=$?
  rm -rf testemptycert
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

PATH="./:${PATH}"
export PATH

touch testemptycert

#LANG=C
#export LANG

(
  ls testcerts | grep '^badkey-' |\
  while read name; do
    tlswrapper-test -r tlswrappernojail -vf "testcerts/${name}" true 2>&1
    echo $?
  done
) | sed 's/ (.*)//'

#echo 'tlswrapper rejects empty PEM cert.'
#tlswrapper-test -qr tlswrappernojail -vf testemptycert true 2>&1
#echo $?; echo
#echo 'tlswrapper rejects unsupported PEM cert.'
#tlswrapper-test -qr tlswrappernojail -vf testcerts/server-ec-prime256v1-ec-secp224r1-unsupported true 2>&1
#echo $?; echo
