#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 /path/to/c-ares /path/to/build-dir [output-binary]" >&2
  exit 2
fi

srcdir=$1
builddir=$2
out=${3:-cares_tcp_uaf_calc_poc}
jobs=${JOBS:-4}
root=$(cd "$(dirname "$0")/.." && pwd)

cmake -S "$srcdir" -B "$builddir" \
  -DCARES_SHARED=OFF \
  -DCARES_STATIC=ON \
  -DCARES_BUILD_TESTS=OFF \
  -DCARES_BUILD_TOOLS=OFF \
  -DCMAKE_BUILD_TYPE=Debug

cmake --build "$builddir" --target c-ares --parallel "$jobs"

gcc -static -g -O0 -Wall -Wextra \
  -I"$srcdir/include" \
  -I"$builddir" \
  "$root/poc/cares_tcp_uaf_calc_poc.c" \
  "$builddir/lib/libcares.a" \
  -pthread \
  -o "$out"

file "$out"
