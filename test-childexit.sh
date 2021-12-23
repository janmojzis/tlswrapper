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
echo 'OK
' > data.in

TCPREMOTEIP=1.2.3.4; export TCPREMOTEIP
TCPREMOTEPORT=1234; export TCPREMOTEPORT
TCPLOCALIP=1.2.3.4; export TCPLOCALIP
TCPLOCALPORT=1234; export TCPLOCALPORT

CMD="tlswrapper-test -q"
CMD="${CMD} -d `cat testcerts/days`"
CMD="${CMD} -a testcerts/ca-ec-prime256v1.pem"
CMD="${CMD} -h okcert-ec-prime256v1-ec-prime256v1-ok.pem"
CMD="${CMD} -w tlswrappernojail -Q -d testcerts"

for i in 'HUP' 'INT' 'KILL' 'TERM'; do
  echo "child killed by SIG${i}"
  ( ${CMD} sh -c "kill -${i} \$\$" <data.in 2>&1; echo $?; ) | sed 's/ (.*)/ /'
done

for i in `seq 0 255`; do
  echo "child exited with status ${i}"
  ( ${CMD} sh -c "exit $i" <data.in 2>&1; echo $?; )
done
