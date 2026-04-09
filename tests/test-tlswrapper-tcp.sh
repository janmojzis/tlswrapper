#!/bin/sh

PATH="./:${PATH}"
export PATH

python3 test-tlswrapper-tcp.py 2>&1
