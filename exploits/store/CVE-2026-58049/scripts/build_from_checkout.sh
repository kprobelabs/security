#!/usr/bin/env bash
set -euo pipefail

src="${1:?usage: build_from_checkout.sh /path/to/ffmpeg-checkout [build-dir] [output-bin]}"
build="${2:-/tmp/ffmpeg-rasc-dlta-build}"
out="${3:-./ffmpeg_rasc_dlta_calc_poc}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
jobs="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}"
cc="${CC:-gcc}"

mkdir -p "$build"
cd "$build"

"$src/configure" \
  --enable-debug \
  --disable-doc \
  --disable-stripping \
  --disable-x86asm \
  --disable-programs \
  --disable-autodetect \
  --disable-everything \
  --enable-zlib \
  --enable-decoder=rasc

make -j"$jobs" libavcodec/libavcodec.a libavutil/libavutil.a

"$cc" -g -O0 \
  -I"$build" \
  -I"$src" \
  "$root/poc/ffmpeg_rasc_dlta_calc_poc.c" \
  "$build/libavcodec/libavcodec.a" \
  "$build/libavutil/libavutil.a" \
  -lz -lm -pthread -ldl \
  -o "$out"

printf '%s\n' "$out"
