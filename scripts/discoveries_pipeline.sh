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
HEALTH_FILE="${THREAT_INTEL_PIPELINE_HEALTH:-$DASHBOARD_DIR/pipeline-health.json}"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAGE="init"
APPEND_OUTPUT=""
MERGE_OUTPUT=""

write_health() {
  local status="$1"
  local stage="$2"
  local exit_code="${3:-0}"
  local message="${4:-}"
  PIPE_STATUS="$status" \
  PIPE_STAGE="$stage" \
  PIPE_EXIT_CODE="$exit_code" \
  PIPE_MESSAGE="$message" \
  PIPE_STARTED_AT="$STARTED_AT" \
  PIPE_FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  PIPE_APPEND_OUTPUT="$APPEND_OUTPUT" \
  PIPE_MERGE_OUTPUT="$MERGE_OUTPUT" \
  PIPE_GENERATED_FILE="$GENERATED_FILE" \
  PIPE_HEALTH_FILE="$HEALTH_FILE" \
  python3 <<'PY'
import json
import os
from pathlib import Path


def parse_json(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return {'raw': value}


generated = Path(os.environ['PIPE_GENERATED_FILE'])
generated_items = None
if generated.exists():
    try:
        data = json.loads(generated.read_text(encoding='utf-8'))
        generated_items = len(data) if isinstance(data, list) else None
    except Exception:
        generated_items = None

payload = {
    'status': os.environ['PIPE_STATUS'],
    'stage': os.environ['PIPE_STAGE'],
    'exit_code': int(os.environ['PIPE_EXIT_CODE']),
    'message': os.environ.get('PIPE_MESSAGE') or '',
    'started_at': os.environ['PIPE_STARTED_AT'],
    'finished_at': os.environ['PIPE_FINISHED_AT'],
    'generated_file': str(generated),
    'generated_items': generated_items,
    'append': parse_json(os.environ.get('PIPE_APPEND_OUTPUT', '')),
    'merge': parse_json(os.environ.get('PIPE_MERGE_OUTPUT', '')),
}

health = Path(os.environ['PIPE_HEALTH_FILE'])
health.parent.mkdir(parents=True, exist_ok=True)
health.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
PY
}

on_error() {
  local rc=$?
  write_health "failed" "$STAGE" "$rc" "Pipeline failed during $STAGE"
  exit "$rc"
}

trap on_error ERR

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
  STAGE="generate"
  python3 "$GENERATE_SCRIPT" >/dev/null
elif needs_capture; then
  STAGE="capture"
  python3 "$CAPTURE_SCRIPT" "$RUNS_FILE" "$GENERATED_FILE"
fi

STAGE="append"
APPEND_OUTPUT="$(python3 "$APPEND_SCRIPT" "$GENERATED_FILE")"
echo "$APPEND_OUTPUT"

STAGE="merge"
MERGE_OUTPUT="$(python3 "$MERGE_SCRIPT")"
echo "$MERGE_OUTPUT"

STAGE="completed"
write_health "ok" "$STAGE" 0 "Pipeline completed"
