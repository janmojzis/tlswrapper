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
    ca.sh "${catype}" ${casize} > ca-${catype}-${casize}.pem

    # auth ca
    #ca.sh "${catype}" ${casize} > auth-${catype}-${casize}.pem


    (
      echo "ec prime256v1"
      echo "ec secp384r1"
      echo "ec secp521r1"
      echo "rsa 2048"
      echo "rsa 3072"
      echo "rsa 4096"
    ) | (
      while read type size; do
        sname="server-${catype}-${casize}-${type}-${size}-ok"
        server.sh "ca-${catype}-${casize}.pem" "${type}" "${size}" "${sname}" > "${sname}"
        #cname="client-${catype}-${casize}-${type}-${size}-ok"
        #client.sh "auth-${catype}-${casize}.pem" "${type}" "${size}" "${cname}" > "${cname}"
      done
    )
  done
)

seconds=`date +"%s"`
days=`expr "${seconds}" / 86400 + 719528 + 2`
echo "${days}"> days
