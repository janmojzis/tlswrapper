#!/bin/sh
set -e

[ x"$1" = x ] && exit 1
type=$1
shift

[ x"$1" = x ] && exit 1
size=$1
shift

umask 077

tmp=`mktemp -d`
[ -d "${tmp}" ] || exit 111

cleanup() {
  ex=$?
  if [ ${ex} -ne 0 ]; then
    cat "${tmp}/ca.log" >&2
  fi
  rm -rf "${tmp}"
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

(
  cd "${tmp}"
  exec 2>ca.log

  (
    echo "[req]"
    echo "distinguished_name = req_distinguished_name"
    echo "req_extensions=v3_req"
    echo "[req_distinguished_name]"
    echo "[v3_req]"
    #echo "basicConstraints=CA:TRUE,pathlen:0"
    echo "basicConstraints=CA:TRUE"
    echo "subjectKeyIdentifier = hash"
    echo "#authorityKeyIdentifier = keyid:always,issuer:always"
    echo "keyUsage = cRLSign, keyCertSign"
  ) > "ca.conf"

  if [ x"${type}" = xrsa ]; then
    openssl genrsa -out "ca.key" "${size}"
  fi
  if [ x"${type}" = xec ]; then
    openssl ecparam -out "ca.key" -name "${size}" -genkey
  fi
  openssl req -new -nodes -sha256 -key ca.key -out ca.csr -config ca.conf -subj "/CN=test CA"

  sed -i 's/^#authorityKeyIdentifier/authorityKeyIdentifier/' ca.conf

  id=0x`sha512sum < ca.csr | cut -b1-32`
  openssl x509 -sha256 -req -days 4 -extfile ca.conf -in ca.csr -signkey ca.key -set_serial "${id}" -out ca.crt -extensions v3_req
  cat ca.key ca.crt
)
