# ASLR bypass analysis

This repository contains an ASLR-on exploit for a local heap/libio profile. It
does not contain a deterministic universal ASLR bypass for the unmodified
`objdump` process.

## What works

The payload set can reach the helper command `P` with ASLR enabled when the
heap and libc low-word layout matches one of the generated profiles.

The current generator emits:

- `orig`: the first measured profile.
- `wsl2404`: offsets measured against the pinned `dlx-elf` build on
  WSL/Ubuntu 24.04.
- `gnu2461`: offsets measured against a clean GNU Binutils 2.46.1 `dlx-elf`
  objdump build.

The `wsl2404` profile uses:

```text
off_io=-0x3690
off_sec=0xbb0
rbase=0x220
buf_delta=0x702fff00 or 0x6f300000
system_delta=0x7042e500, 0x6f42e600, 0x7043e4ff, 0x6f43e5ff, 0x7043e5ff, or 0x6f43e6ff
```

The `gnu2461` profile uses:

```text
off_io=-0x3690
off_sec=0xbb8
sec_size_offset=0x40
rbase=0x190
buf_delta=0x702fff00 or 0x6f300000
system_delta=0x7042e500, 0x6f42e600, 0x7043e4ff, 0x6f43e5ff, 0x7043e5ff, or 0x6f43e6ff
```

The 2.46.1 profile differs because the relocation cache array moved from
`data+0x220` to `data+0x190`, the BFD section object moved from `data+0xbb0`
to `data+0xbb8`, and the `bfd_section.size` field used to widen generic
relocation range checks is at section offset `0x40`.

## Fixed delta coverage

The `FILE+0x68` field starts as a libc pointer to `_IO_2_1_stderr_`. The
payload uses a 32-bit big-endian relocation add to turn that low 32-bit value
into the low 32 bits of `system`.

The previous payload set included two deltas. For the documented offsets:

```text
_IO_2_1_stderr_ offset = 0x2044e0
system offset          = 0x58750
```

there are six possible deltas over all page-aligned low-32-bit libc bases:

```text
0x7042e500 pages=703488 coverage=0.670898 cumulative=0.670898
0x6f42e600 pages=235520 coverage=0.224609 cumulative=0.895508
0x7043e4ff pages=82620 coverage=0.078793 cumulative=0.974300
0x6f43e5ff pages=26520 coverage=0.025291 cumulative=0.999592
0x7043e5ff pages=324 coverage=0.000309 cumulative=0.999901
0x6f43e6ff pages=104 coverage=0.000099 cumulative=1.000000
```

`tools/aslr_delta_coverage.py` reproduces that table. This is better coverage
for the libc low-32 portion of the bypass, not a claim that the heap/libio
profile is universal.

## Why argv two-stage is not enough

A deterministic leak-then-exploit route would need this sequence in one
`objdump` process:

1. Process file 1 and leak libc.
2. Generate file 2 with the exact `system` delta.
3. Process file 2 with the same ASLR layout.

That path did not hold for this trigger. In local GDB measurements with
`objdump -W -r file1 file2`, the DWARF relocation side effect that mutates
`.debug_info` ran for the first object only. The second object's relocation
table printed unmodified symbol names (`s0`, `s1`, and so on).

FIFO staging is also blocked in unmodified `objdump`: `display_file()` calls
`get_file_size()`, and `get_file_size()` rejects non-regular files before
`bfd_openr()`.

## Why a fixed single-file transform is not universal

The useful dynamic value in the corrupted `FILE` object is the existing libc
pointer at `FILE+0x68`:

```text
_IO_2_1_stderr_ offset = 0x2044e0
system offset          = 0x58750
```

For a page-aligned libc base, converting `P = base + 0x2044e0` into
`S = base + 0x58750` requires carry/borrow information from lower
little-endian bytes.

Counterexample over low 32 bits:

```text
base_low = 0x0000: P bytes = e0 44 20 00, S bytes = 50 87 05 00
base_low = 0x8000: P bytes = e0 c4 20 00, S bytes = 50 07 06 00
```

The original byte 2 and byte 3 are identical in both cases (`20 00`), but the
desired byte 2 differs (`05` versus `06`) based on original byte 1.

The DLX relocation additions available to the payload operate on big-endian
8/16/32-bit fields in the target byte stream. Their carries flow from higher
memory offsets toward lower memory offsets. They cannot make final byte 2
depend on original byte 1. PC-relative writes can set constants, but they do
not introduce the missing dependency.

`tools/search_pointer_transform.py` is a sanity check for this reasoning. It
asks Z3 for fixed sequences consisting of one 32-bit relocation plus up to a
chosen number of 8/16-bit correction relocations, then brute-verifies any
candidate over all page-aligned low-32-bit bases.

Example:

```bash
python3 tools/search_pointer_transform.py --mode r32-first --max-extra 4
python3 tools/search_pointer_transform.py --mode r32-last --max-extra 4
```

Both forms found no universal transform up to four correction relocations in
the tested operation class.

## Result

The PoC should be described as ASLR-on and profile-dependent. It is not a
universal single-file ASLR bypass.
