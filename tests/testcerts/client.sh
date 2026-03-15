#!/bin/sh
set -e

[ x"$1" = x ] && exit 1
ca=$1
shift

[ x"$1" = x ] && exit 1
type=$1
shift

[ x"$1" = x ] && exit 1
size=$1
shift

[ x"$1" = x ] && exit 1
name=$1
shift

if [ x"$1" = x ]; then
  email="${name}@example.com"
else
  email=$1
fi

umask 077
tmp=`mktemp -d`
[ -d "${tmp}" ] || exit 111
cp -p "${ca}" "${tmp}/"

cleanup() {
  ex=$?
  if [ ${ex} -ne 0 ]; then
    cat "${tmp}/${name}.log" >&2
  fi
  rm -rf "${tmp}"
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

(
  cd "${tmp}"
  exec 2>"${name}.log"

  (
    echo "[req]"
    echo "distinguished_name = req_distinguished_name"
    echo "req_extensions=v3_req"
    echo "[req_distinguished_name]"
    echo "[v3_req]"
    echo "basicConstraints=CA:FALSE"
    echo "subjectKeyIdentifier=hash"
    echo "#authorityKeyIdentifier = keyid,issuer:always"
    echo "extendedKeyUsage=clientAuth"
    echo "keyUsage=digitalSignature"
  ) > "${name}.conf"

  if [ x"${type}" = xrsa ]; then
    openssl genrsa -out "${name}.key" "${size}"
  fi
  if [ x"${type}" = xec ]; then
    openssl ecparam -out "${name}.key" -name "${size}" -genkey
  fi
  openssl req -new -sha256 -key "${name}.key" -out "${name}.csr" -config "${name}.conf" -subj "/emailAddress=${email}/CN=${name}"

  sed -i 's/^#authorityKeyIdentifier/authorityKeyIdentifier/' "${name}.conf"

  id=0x`sha512sum < "${name}.csr" | cut -b1-32`
  openssl x509 -sha256 -req -days 4 -extfile "${name}.conf" -in "${name}.csr" -CA "${ca}" -CAkey "${ca}" -set_serial "${id}" -out "${name}.crt" -extensions v3_req
  cat "${name}.key" "${name}.crt"
)
