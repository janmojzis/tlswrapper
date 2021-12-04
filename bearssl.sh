#!/bin/sh
set -e

version="0.6"
name="bearssl-${version}"
tarball="${name}.tar.gz"
chsum='6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14'

rm -rf bearssl

if [ ! -f "${tarball}" ]; then
  curl -sk "https://www.bearssl.org/${tarball}" > "${tarball}.tmp"
  sum=`cat "${tarball}.tmp" | (shasum256 2>/dev/null || shasum -a 256) | cut -d ' ' -f1`
  if [ x"${sum}" != x"${chsum}" ]; then
    echo "bad ${tarball} checksum !!!" >&2
    echo "expected: ${chsum}" >&2
    echo "downloaded: ${sum}" >&2
    exit 111
  fi
  mv -f "${tarball}.tmp" "${tarball}"
fi

if [ ! -d "${name}" ]; then
  tar -ozxf "${tarball}"
fi

mv "${name}" bearssl
exit 0
