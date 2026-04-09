#!/bin/sh

cleanup() {
  ex=$?
  rm -rf test-tlswrapper-smtp-child.log
  exit "${ex}"
}
trap "cleanup" EXIT TERM INT

python3 test-tlswrapper-smtp.py --child-log test-tlswrapper-smtp-child.log 2>&1
