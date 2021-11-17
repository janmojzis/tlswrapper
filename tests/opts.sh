#!/bin/sh
set -e

rm -rf filecert.pem dircert linkcert fifocert.pem
touch filecert.pem
mkdir dircert
ln -s dircert linkcert
mkfifo fifocert.pem

cleanup() {
  ex=$?
  if [ "${ex}" -ne 0 ]; then
    echo "log:" >&2
    cat log >&2
  fi
  rm -rf filecert.pem dircert linkcert fifocert.pem log
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

# server preferences
../tlswrapper -f filecert.pem -p true </dev/null 1>/dev/null 2>log || { echo "tlswrapper doesn't accept -p" >&2; exit 1; }
../tlswrapper -f filecert.pem -P true </dev/null 1>/dev/null 2>log || { echo "tlswrapper doesn't accept -P" >&2; exit 1; }

# TLS version
../tlswrapper -f filecert.pem -m tls00 true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -m accepts bad TLS version" >&2; exit 1; }
../tlswrapper -f filecert.pem -M tls00 true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -M accepts bad TLS version" >&2; exit 1; }
../tlswrapper -f filecert.pem -m tls10 true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -m doesn't accept tls10" >&2; exit 1; }
../tlswrapper -f filecert.pem -m tls11 true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -m doesn't accept tls11" >&2; exit 1; }
../tlswrapper -f filecert.pem -m tls12 true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -m doesn't accept tls12" >&2; exit 1; }
../tlswrapper -f filecert.pem -M tls10 true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -M doesn't accept tls10" >&2; exit 1; }
../tlswrapper -f filecert.pem -M tls11 true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -M doesn't accept tls11" >&2; exit 1; }
../tlswrapper -f filecert.pem -M tls12 true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -M doesn't accept tls12" >&2; exit 1; }

# timeouts
../tlswrapper -f filecert.pem -t 1 true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -t doesn't accept number" >&2; exit 1; }
../tlswrapper -f filecert.pem -t 0 true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -t accepts zero timeout" >&2; exit 1; }
../tlswrapper -f filecert.pem -t -1 true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -t accepts negative number" >&2; exit 1; }
../tlswrapper -f filecert.pem -t x true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -t accepts bad number" >&2; exit 1; }
../tlswrapper -f filecert.pem -T 1 true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -T doesn't accept number" >&2; exit 1; }
../tlswrapper -f filecert.pem -T 0 true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -T accepts zero timeout" >&2; exit 1; }
../tlswrapper -f filecert.pem -T -1 true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -T accepts negative number" >&2; exit 1; }
../tlswrapper -f filecert.pem -T x true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -T accepts bad number" >&2; exit 1; }

# certs
../tlswrapper -f notexist true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -f accepts non-existent file" >&2; exit 1; }
../tlswrapper -f fifocert.pem true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -f accepts FIFO instead of certfile" >&2; exit 1; }
../tlswrapper -f dircert true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -f accepts certdir instead of certfile" >&2; exit 1; }
../tlswrapper -f filecert.pem true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -f doesn't accept certfile" >&2; exit 1; }
../tlswrapper -d notexist true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -d accepts non-existent directory" >&2; exit 1; }
../tlswrapper -d fifocert.pem true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -d accepts FIFO instead of certdir" >&2; exit 1; }
../tlswrapper -d filecert.pem true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -d accepts certfile instead of certdir" >&2; exit 1; }
../tlswrapper -d dircert true </dev/null 1>/dev/null 2>log && { echo "tlswrapper -d accepts relative certdir path" >&2; exit 1; }
../tlswrapper -d `pwd`/dircert true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -d doesn't accept certdir" >&2; exit 1; }
../tlswrapper -d `pwd`/linkcert true </dev/null 1>/dev/null 2>log || { echo "tlswrapper -d doesn't accept symlink to certdir" >&2; exit 1; }
