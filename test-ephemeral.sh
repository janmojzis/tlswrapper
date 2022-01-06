#!/bin/sh

cleanup() {
  ex=$?
  rm -rf tlswrappernojail data.in
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

PATH="./:${PATH}"
export PATH

ln -s tlswrapper-test tlswrappernojail
echo 'OK' > data.in

TCPREMOTEIP=1.2.3.4; export TCPREMOTEIP
TCPREMOTEPORT=1234; export TCPREMOTEPORT
TCPLOCALIP=1.2.3.4; export TCPLOCALIP
TCPLOCALPORT=1234; export TCPLOCALPORT

echo "tests default ephemeral ciphers"
CMD="tlswrapper-test -q"
CMD="${CMD} -d `cat testcerts/days`"
CMD="${CMD} -a testcerts/ca-rsa-2048.pem"
CMD="${CMD} -h okcert-rsa-2048-rsa-2048-ok.pem"
(
  echo "x25519"
  echo "secp256r1"
  echo "secp384r1"
  echo "secp521r1"
) | (
  while read cipher; do
    echo "${cipher}"
    ${CMD} -e "${cipher}" -w tlswrappernojail -Q -d testcerts sh -c 'cat >&2' <data.in 2>&1; echo $?;
  done
)

echo "tests all ephemeral ciphers"
CMD="tlswrapper-test -q"
CMD="${CMD} -d `cat testcerts/days`"
CMD="${CMD} -a testcerts/ca-rsa-2048.pem"
CMD="${CMD} -h okcert-rsa-2048-rsa-2048-ok.pem"
allecdhe="-e x25519 -e secp256r1 -e secp384r1 -e secp521r1"
(
  echo "x25519"
  echo "secp256r1"
  echo "secp384r1"
  echo "secp521r1"
) | (
  while read cipher; do
    echo "${cipher}"
    ${CMD} -e "${cipher}" -w tlswrappernojail ${allecdhe} -Q -d testcerts sh -c 'cat >&2' <data.in 2>&1; echo $?;
  done
)
