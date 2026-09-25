set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHP_BIN="${PHP_BIN:-${1:-}}"
POC="$ROOT/poc/rpoc.php"
LOG="$ROOT/evidence/local-validation.txt"

if [[ -z "$PHP_BIN" ]]; then
  echo "usage: PHP_BIN=/path/to/php scripts/validate.sh"
  echo "usage: scripts/validate.sh /path/to/php"
  exit 2
fi

mkdir -p "$ROOT/evidence"
"$PHP_BIN" -n "$POC" | tee "$LOG"

MARKER_PATH="$(awk -F= '/^marker_path=/{print $2; exit}' "$LOG")"
if [[ -z "$MARKER_PATH" || ! -f "$MARKER_PATH" ]]; then
  echo "marker_check=missing" | tee -a "$LOG"
  exit 1
fi

MARKER_CONTENT="$(cat "$MARKER_PATH")"
echo "marker_check=present" | tee -a "$LOG"
echo "marker_content=$MARKER_CONTENT" | tee -a "$LOG"
[[ "$MARKER_CONTENT" == "PHP857_RCE" ]]
