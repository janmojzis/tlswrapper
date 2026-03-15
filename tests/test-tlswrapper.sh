#!/bin/sh

PATH="./:${PATH}"
export PATH

cleanup() {
  ex=$?
  rm -f test-tlswrapper-child.log
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

tests="control_pipe_eof_before_starttls"

for t in ${tests}; do
  echo "=== ${t} ==="
  python3 test-tlswrapper.py "${t}" 2>&1
  echo
done
