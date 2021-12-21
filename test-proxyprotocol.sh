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
echo "OK" > data.in

CMD="tlswrapper-test -q"
CMD="${CMD} -d `cat testcerts/days`"
CMD="${CMD} -a testcerts/ca-ec-prime256v1.pem"
CMD="${CMD} -h okcert-ec-prime256v1-ec-prime256v1-ok.pem"
${CMD} -w tlswrappernojail -P1 -d "`pwd`/testcerts" sh -c 'exec cat >&9' <data.in 9>&1 2>&1
${CMD} -w tlswrappernojail -P2 -d "`pwd`/testcerts" sh -c 'exec cat >&9' <data.in 9>&1 2>&1

(
  echo "PROXY_TCP6_::_::_65535_65535"
  echo "PROXY_TCP4_255.255.255.255_255.255.255.255_65535_65535"
  echo "PROXY"
  echo "PROXY_UNKNOWN"
  echo "PROXY_TCP6"
  echo "PROXY_TCP4_"
  echo "PROXY_TCP4_2"
  echo "PROXY_TCP4_255"
  echo "PROXY_TCP4_255."
  echo "PROXY_TCP4_255.255.255.255"
  echo "PROXY_TCP4_255.255.255.255_"
  echo "PROXY_TCP4_255.255.255.255_255.255.255.255"
  echo "PROXY_TCP4_255.255.255.255_255.255.255.255_"
  echo "PROXY_TCP4_255.255.255.255_255.255.255.255_65535"
  echo "PROXY_TCP4_255.255.255.255_255.255.255.255_65535_"
  echo "PROXY_TCP4_255.255.256.255_255.255.255.255_65535_"
  echo "PROXY_TCP4_255.256.255.255_255.255.255.255_65535_65535"
  echo "PROXY_TCP4_255.255.255.255_255.256.255.255_65535_65535"
  echo "PROXY_TCP4_255.255.255.255_255.255.255.255_65536_65535"
  echo "PROXY_TCP4_255.255.255.255_255.255.255.255_65535_65536"
) | while read line; do
  ${CMD} -P "${line}" -w tlswrappernojail -p1 -P1 -d "`pwd`/testcerts" -v sh -c 'exec cat >&9' <data.in 9>&1 2>&1
done
