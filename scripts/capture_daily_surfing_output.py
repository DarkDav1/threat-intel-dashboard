#!/usr/bin/env python3
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(os.environ.get('THREAT_INTEL_ROOT', Path(__file__).resolve().parents[1]))
DASHBOARD_DIR = Path(os.environ.get('THREAT_INTEL_DASHBOARD_DIR', ROOT / 'dashboard'))
DEFAULT_RUNS = Path(os.environ.get('THREAT_INTEL_RUNS_FILE', ROOT / 'runs' / 'daily_surfing.jsonl'))
DEFAULT_OUT = Path(os.environ.get('THREAT_INTEL_OUTPUT', DASHBOARD_DIR / 'discoveries-generated.json'))
ALLOWED_KINDS = {
    'threat_intel', 'cve_radar', 'defender_actions'
}


def extract_json_array(text: str):
    text = text.strip()
    if not text:
        raise ValueError('empty summary')
    candidates = []
    if text.startswith('[') and text.endswith(']'):
        candidates.append(text)
    candidates.extend(re.findall(r'(\[.*\])', text, flags=re.S))
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except Exception:
            continue
        if isinstance(data, list):
            return data
    raise ValueError('no JSON array found in summary')


def validate_items(data):
    clean = []
    for item in data:
        if not isinstance(item, dict):
            continue
        kind = item.get('kind')
        date = item.get('date')
        title = item.get('title')
        content = item.get('content')
        if kind not in ALLOWED_KINDS:
            continue
        if not all(isinstance(v, str) and v.strip() for v in [kind, date, title, content]):
            continue
        clean.append({
            'kind': kind.strip(),
            'date': date.strip(),
            'title': title.strip(),
            'content': content.strip(),
        })
    return clean


def main():
    runs = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_RUNS
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUT
    if len(sys.argv) > 3:
        raise SystemExit('usage: capture_daily_surfing_output.py [runs-jsonl] [out-json]')
    if not runs.exists():
        raise SystemExit(f'runs file missing: {runs}')
    lines = [line for line in runs.read_text(encoding='utf-8').splitlines() if line.strip()]
    last_error = None
    for line in reversed(lines):
        try:
            event = json.loads(line)
        except Exception:
            continue
        if event.get('action') != 'finished' or event.get('status') != 'ok':
            continue
        summary = event.get('summary')
        if not isinstance(summary, str):
            continue
        try:
            data = extract_json_array(summary)
            clean = validate_items(data)
        except Exception as e:
            last_error = str(e)
            continue
        out.write_text(json.dumps(clean, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({
            'captured_from_ts': event.get('ts'),
            'items': len(clean),
            'output': str(out)
        }, ensure_ascii=False))
        return
    raise SystemExit(last_error or 'no successful JSON-producing daily_surfing run found')


if __name__ == '__main__':
    main()
