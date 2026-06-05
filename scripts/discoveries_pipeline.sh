#!/usr/bin/env bash
set -euo pipefail

ROOT="${THREAT_INTEL_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DASHBOARD_DIR="${THREAT_INTEL_DASHBOARD_DIR:-$ROOT/dashboard}"
CAPTURE_SCRIPT="$ROOT/scripts/capture_daily_surfing_output.py"
APPEND_SCRIPT="$ROOT/scripts/append_discoveries_json_to_inbox.py"
MERGE_SCRIPT="$ROOT/scripts/merge_discoveries_inbox.py"
GENERATE_SCRIPT="$ROOT/scripts/generate_threat_intel.py"
RUNS_FILE="${THREAT_INTEL_RUNS_FILE:-$ROOT/runs/daily_surfing.jsonl}"
GENERATED_FILE="${THREAT_INTEL_OUTPUT:-$DASHBOARD_DIR/discoveries-generated.json}"

needs_capture() {
  if [ ! -s "$GENERATED_FILE" ]; then
    return 0
  fi

  set +e
  python3 - "$GENERATED_FILE" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding='utf-8'))
except Exception:
    sys.exit(10)

if data == []:
    sys.exit(11)
if not isinstance(data, list):
    sys.exit(12)
sys.exit(0)
PY
  rc=$?
  set -e

  case "$rc" in
    0)
      return 1
      ;;
    10)
      bad_file="${GENERATED_FILE}.bad.$(date +%Y%m%d%H%M%S)"
      cp "$GENERATED_FILE" "$bad_file"
      echo "Backed up invalid generated file: $bad_file"
      return 0
      ;;
    11|12)
      return 0
      ;;
    *)
      return "$rc"
      ;;
  esac
}

if [ -x "$GENERATE_SCRIPT" ]; then
  python3 "$GENERATE_SCRIPT" >/dev/null
elif needs_capture; then
  python3 "$CAPTURE_SCRIPT" "$RUNS_FILE" "$GENERATED_FILE"
fi

python3 "$APPEND_SCRIPT" "$GENERATED_FILE"
python3 "$MERGE_SCRIPT"
