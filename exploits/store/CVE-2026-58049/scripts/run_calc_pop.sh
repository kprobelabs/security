#!/usr/bin/env bash
set -euo pipefail

bin="${1:-./ffmpeg_rasc_dlta_calc_poc}"
marker="/tmp/ffmpeg_rasc_exec_demo"

rm -f "$marker"
"$bin"
sleep 2

if [ -f "$marker" ]; then
  echo "marker:present"
else
  echo "marker:missing"
  exit 1
fi

if command -v powershell.exe >/dev/null 2>&1; then
  powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzACAAQwBhAGwAYwB1AGwAYQB0AG8AcgBBAHAAcAAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAAUAByAG8AYwBlAHMAcwBOAGEAbQBlACwASQBkACwAUwB0AGEAcgB0AFQAaQBtAGUA 2>/dev/null || true
fi
