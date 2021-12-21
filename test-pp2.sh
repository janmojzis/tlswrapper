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
${CMD} -w tlswrappernojail -P2 -d "`pwd`/testcerts" sh -c 'exec cat >&9' <data.in 9>&1 2>&1
TCPREMOTEIP=1.2.3.4; export TCPREMOTEIP
TCPREMOTEPORT=1234; export TCPREMOTEPORT
TCPLOCALIP=1.2.3.4; export TCPLOCALIP
TCPLOCALPORT=1234; export TCPLOCALPORT
${CMD} -w tlswrappernojail -P2 -d "`pwd`/testcerts" sh -c 'exec cat >&9' <data.in 9>&1 2>&1
TCPREMOTEIP="abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd"; export TCPREMOTEIP
TCPREMOTEPORT=1234; export TCPREMOTEPORT
TCPLOCALIP=abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd; export TCPLOCALIP
TCPLOCALPORT=1234; export TCPLOCALPORT
${CMD} -w tlswrappernojail -P2 -d "`pwd`/testcerts" sh -c 'exec cat >&9' <data.in 9>&1 2>&1

(
  echo "PROXY_UNKNOWN"
  echo "PROXY_TCP6_ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff_ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff_65535_65535"
  echo "PROXY_TCP6_ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255_ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255_65535_65535"
  echo "PROXY_TCP4_255.255.255.255_255.255.255.255_65535_65535"
) | while read line; do
  ${CMD} -P "${line}" -w tlswrappernojail -p1 -P2 -d "`pwd`/testcerts" sh -c 'exec cat >&9' <data.in 9>&1 2>&1
done
