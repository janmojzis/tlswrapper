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

echo "tests default ECDSA ciphers"
CMD="tlswrapper-test -q"
CMD="${CMD} -d `cat testcerts/days`"
CMD="${CMD} -a testcerts/ca-ec-prime256v1.pem"
CMD="${CMD} -h okcert-ec-prime256v1-ec-prime256v1-ok.pem"
(
  echo "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
  echo "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
  echo "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
  echo "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
  echo "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
  echo "ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
  echo "ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
  echo "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
) | (
  while read cipher; do
    echo "${cipher}"
    ${CMD} -w -c "${cipher}" tlswrappernojail -Q -d testcerts sh -c 'cat >&2' <data.in 2>&1; echo $?;
  done
)

echo "tests default RSA ciphers"
CMD="tlswrapper-test -q"
CMD="${CMD} -d `cat testcerts/days`"
CMD="${CMD} -a testcerts/ca-rsa-2048.pem"
CMD="${CMD} -h okcert-rsa-2048-rsa-2048-ok.pem"
(
  echo "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
  echo "ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  echo "ECDHE_RSA_WITH_AES_256_GCM_SHA384"
  echo "ECDHE_RSA_WITH_AES_128_CBC_SHA256"
  echo "ECDHE_RSA_WITH_AES_256_CBC_SHA384"
  echo "ECDHE_RSA_WITH_AES_128_CBC_SHA"
  echo "ECDHE_RSA_WITH_AES_256_CBC_SHA"
  echo "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
) | (
  while read cipher; do
    echo "${cipher}"
    ${CMD} -w -c "${cipher}" tlswrappernojail -Q -d testcerts sh -c 'cat >&2' <data.in 2>&1; echo $?;
  done
)

echo "tests all ciphers"
CMD="tlswrapper-test -q"
CMD="${CMD} -d `cat testcerts/days`"
CMD="${CMD} -a testcerts/ca-ec-prime256v1.pem"
allciphers="\
-c CHACHA20_POLY1305_SHA256 \
-c AES_256_GCM_SHA384 \
-c AES_128_GCM_SHA256 \
-c AES_256_CBC_SHA384 \
-c AES_128_CBC_SHA256 \
-c AES_256_CBC_SHA \
-c AES_128_CBC_SHA"
(
  echo "ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 okcert-ec-prime256v1-ec-prime256v1-ok.pem"
  echo "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 okcert-ec-prime256v1-ec-prime256v1-ok.pem"
  echo "ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 okcert-ec-prime256v1-ec-prime256v1-ok.pem"
  echo "ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 okcert-ec-prime256v1-ec-prime256v1-ok.pem"
  echo "ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 okcert-ec-prime256v1-ec-prime256v1-ok.pem"
  echo "ECDHE_ECDSA_WITH_AES_128_CBC_SHA okcert-ec-prime256v1-ec-prime256v1-ok.pem"
  echo "ECDHE_ECDSA_WITH_AES_256_CBC_SHA okcert-ec-prime256v1-ec-prime256v1-ok.pem"
  echo "ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA okcert-ec-prime256v1-ec-prime256v1-ok.pem"
  echo "ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 okcert-ec-prime256v1-rsa-2048-ok.pem"
  echo "ECDHE_RSA_WITH_AES_128_GCM_SHA256 okcert-ec-prime256v1-rsa-2048-ok.pem"
  echo "ECDHE_RSA_WITH_AES_256_GCM_SHA384 okcert-ec-prime256v1-rsa-2048-ok.pem"
  echo "ECDHE_RSA_WITH_AES_128_CBC_SHA256 okcert-ec-prime256v1-rsa-2048-ok.pem"
  echo "ECDHE_RSA_WITH_AES_256_CBC_SHA384 okcert-ec-prime256v1-rsa-2048-ok.pem"
  echo "ECDHE_RSA_WITH_AES_128_CBC_SHA okcert-ec-prime256v1-rsa-2048-ok.pem"
  echo "ECDHE_RSA_WITH_AES_256_CBC_SHA okcert-ec-prime256v1-rsa-2048-ok.pem"
  echo "ECDHE_RSA_WITH_3DES_EDE_CBC_SHA okcert-ec-prime256v1-rsa-2048-ok.pem"
) | (
  while read cipher host; do
    echo "${cipher} "
    ${CMD} -h "${host}" -w -c "${cipher}" tlswrappernojail ${allciphers} -Q -d ./testcerts sh -c 'cat >&2' <data.in 2>&1; echo $?;
  done
)
