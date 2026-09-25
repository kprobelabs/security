# VLC VP9 Resolution-Change Crash PoC

This repository contains a small Python reproducer for a VLC 3.0.23 Windows VP9 decoder crash condition.

Research status: incomplete and continuing.

## Summary

The PoC writes a 405-byte VP9 IVF file with two frames:

- frame 1: `64x64`
- frame 2: `64x8192`

The important detail is that the second frame changes the frame height while keeping the VP9 tile-column layout stable. In VLC 3.0.23's bundled FFmpeg VP9 decoder, that shape reaches a stale slice-thread progress allocation.

## Why It Happens

The VP9 decoder tracks slice-thread progress in an `entries` array. That array is allocated using the number of superblock rows for the current frame.

For a `64x64` frame:

```text
sb_rows = (64 + 63) >> 6 = 1
entries allocation = 1 * sizeof(atomic_int) = 4 bytes
```

For a later `64x8192` frame:

```text
sb_rows = (8192 + 63) >> 6 = 128
```

The stale allocation remains sized for the first frame when the tile-column count does not change. During decode, the VP9 slice-thread reset loop writes zero to each row entry for the new frame:

```c
for (i = 0; i < s->sb_rows; i++)
    atomic_store(&s->entries[i], 0);
```

That turns the second frame into a sequence of 4-byte zero writes past the original 4-byte allocation. On Windows VLC 3.0.23, the process behavior depends on heap layout and runtime state; observed outcomes include heap-corruption termination and access violation.

## Files

- `poc.py`: stdlib-only Python reproducer
- generated output: `vp9_reschange_64x64_to_64x8192_tc0.ivf`

No external Python dependencies are required.

## Usage

Generate the IVF sample:

```bash
python poc.py
```

Generate the sample at a custom path:

```bash
python poc.py -o sample.ivf
```

Optionally replay it with a local VLC binary:

```bash
python poc.py --vlc "C:\Path\To\VLC\vlc.exe"
```

The script prints JSON containing the generated sample path, SHA256 hash, size, and optional VLC process result.

Expected sample hash:

```text
F26BDEFBDFD0B44359E314E0BFDE7AEA979D29F80F598749DCCA68AB34F54649
```

## Tested Target

Tested against:

- VLC media player 3.0.23 for Windows x64
- decoder module: `plugins/codec/libavcodec_plugin.dll`
- VP9 decoder source lineage: FFmpeg 4.4.x VP9 decoder

The relevant decoder behavior is the stale `entries` allocation on a resolution change that does not change tile-column count.

## Research Notes

Local instrumentation observed the stale reset loop in `libavcodec_plugin.dll` at RVA `0x698a5c`, executing the fixed zero-write pattern against the stale `entries` allocation.

For the `64x64 -> 64x8192` sample, direct-store tracing observed:

- `129` total `entries` stores
- `127` stores past the requested 4-byte allocation
- `114` stores past the allocator raw usable block

This repository is a compact crash reproducer. Research on the full exploitability of this primitive is incomplete and continuing.

## Responsible Use

Run this only in a local test environment you control. The generated media file is intended for reproducing and studying the decoder fault path.
