#!/bin/sh

check() {
  if [ x"`shasum < data.in`" = x"`shasum < data.out`" ]; then
    echo "$1 OK"
  else
    echo "$1 FAILED" >&2
    cat log >&2
    exit 1
  fi
}

randdata() {
  # create random datafile
  dd if=/dev/urandom of=data.in bs=1 count=16385 2>/dev/null
}


cleanup() {
  ex=$?
  rm -rf data.in data.out log tlswrappernojail
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

ln -s tlswrapper-test tlswrappernojail

PATH="./:${PATH}"
export PATH

CMD="tlswrapper-test -vvv"
CMD="${CMD} -d `cat testcerts/days`"

ls testcerts | grep '^okcert-' |\
while read name; do
  # get CA name
  catype=`echo ${name} | cut -d- -f2`
  casize=`echo ${name} | cut -d- -f3`
  caname="testcerts/ca-${catype}-${casize}.pem"
  type=`echo ${name} | cut -d- -f4`
  size=`echo ${name} | cut -d- -f5`

  randdata
  CMD="${CMD} -a ${caname} -h "${name}""
  ${CMD} -w tlswrappernojail -v -d "testcerts" sh -c 'cat > data.out' < data.in  2>log
  check "CA=${catype}-${casize}, cert=${type}-${size}, certdir (-d), upload"

  randdata
  ${CMD} -r tlswrappernojail -v -d "testcerts" cat data.in > data.out 2>log
  check "CA=${catype}-${casize}, cert=${type}-${size}, certdir (-d), download"

  randdata
  CMD="${CMD} -a ${caname} -h "${name}""
  ${CMD} -w tlswrappernojail -v -f "testcerts/${name}" sh -c 'cat > data.out' < data.in  2>log
  check "CA=${catype}-${casize}, cert=${type}-${size}, certfile (-f), upload"

  randdata
  ${CMD} -r tlswrappernojail -v -f "testcerts/${name}" cat data.in > data.out 2>log
  check "CA=${catype}-${casize}, cert=${type}-${size}, certfile (-f), download"
done

exit 0
