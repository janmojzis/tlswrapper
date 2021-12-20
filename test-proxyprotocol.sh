#!/bin/sh

cleanup() {
  ex=$?
  rm -rf tlswrappernojail log data.in
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

PATH="./:${PATH}"
export PATH

ln -s tlswrapper-test tlswrappernojail
echo "data" > data.in

CMD="tlswrapper-test -vvv"
CMD="${CMD} -d `cat testcerts/days`"
CMD="${CMD} -a testcerts/ca-ec-prime256v1.pem"
CMD="${CMD} -h okcert-ec-prime256v1-ec-prime256v1-ok.pem"
${CMD} -w tlswrappernojail -p1 -v -d "`pwd`/testcerts" sh -c 'exec cat >&9' <data.in 9>&1 2>log
${CMD} -w tlswrappernojail -p2 -v -d "`pwd`/testcerts" sh -c 'exec cat >&9' <data.in 9>&1 2>log
