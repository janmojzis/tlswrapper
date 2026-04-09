#!/bin/sh

cleanup() {
  ex=$?
  rm -f test-tlswrapper-child.log
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

python3 test-tlswrapper.py --child-log test-tlswrapper-child.log 2>&1
