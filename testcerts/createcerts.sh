#!/bin/sh
set -e

PATH="./:${PATH}"
export PATH

(
  echo "ec prime256v1"
  echo "ec secp384r1"
  echo "ec secp521r1"
  echo "rsa 2048"
  echo "rsa 3072"
  echo "rsa 4096"
) | (
  while read catype casize; do

    # ca
    if [ ! -f "ca-${catype}-${casize}.pem" ]; then
       ca.sh "${catype}" ${casize} > ca-${catype}-${casize}.pem
    fi


    (
      echo "ec prime256v1"
      echo "ec secp384r1"
      echo "ec secp521r1"
      echo "rsa 2048"
      echo "rsa 3072"
      echo "rsa 4096"
    ) | (
      while read type size; do
        name="okcert-${catype}-${casize}-${type}-${size}-ok.pem"
        if [ ! -f "${name}" ]; then
          server.sh "ca-${catype}-${casize}.pem" "${type}" "${size}" "${name}" > "${name}"
        fi
        oname="badcert-${catype}-${casize}-${type}-${size}-keyonly.pem"
        if [ ! -f "${oname}" ]; then
          openssl "${type}" -in "${name}" > "${oname}"
        fi
        oname="badkey-${catype}-${casize}-${type}-${size}-certonly.pem"
        if [ ! -f "${oname}" ]; then
          openssl x509 -in "${name}" > "${oname}"
        fi
      done
    )
    (
      echo "ec secp224r1"
    ) | (
      while read type size; do
        name="badcert-${catype}-${casize}-${type}-${size}-unsupported.pem"
        if [ ! -f "${name}" ]; then
          server.sh "ca-${catype}-${casize}.pem" "${type}" "${size}" "${name}" > "${name}"
        fi
      done
    )
  done
)

seconds=`date +"%s"`
days=`expr "${seconds}" / 86400 + 719528 + 2`
echo "${days}"> days
