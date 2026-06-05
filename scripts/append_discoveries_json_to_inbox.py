#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

ROOT = Path(os.environ.get('THREAT_INTEL_ROOT', Path(__file__).resolve().parents[1]))
DASHBOARD_DIR = Path(os.environ.get('THREAT_INTEL_DASHBOARD_DIR', ROOT / 'dashboard'))
INBOX = Path(os.environ.get('THREAT_INTEL_INBOX', DASHBOARD_DIR / 'discoveries-inbox.json'))
ALLOWED_KINDS = {
    'threat_intel', 'cve_radar', 'defender_actions'
}
OPTIONAL_FIELDS = {'items', 'sources'}


def load_array(path: Path):
    if not path.exists():
        return []
    text = path.read_text(encoding='utf-8').strip()
    if not text:
        return []
    data = json.loads(text)
    if not isinstance(data, list):
        raise SystemExit('inbox is not a JSON array')
    return data


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: append_discoveries_json_to_inbox.py <json-file>')
    src = Path(sys.argv[1])
    data = json.loads(src.read_text(encoding='utf-8'))
    if not isinstance(data, list):
        raise SystemExit('source output must be a JSON array')

    inbox = load_array(INBOX)
    appended = 0
    seen = {(x.get('kind'), x.get('date'), x.get('title')) for x in inbox if isinstance(x, dict)}
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
        key = (kind.strip(), date.strip(), title.strip())
        if key in seen:
            continue
        normalized = {
            'kind': kind.strip(),
            'date': date.strip(),
            'title': title.strip(),
            'content': content.strip(),
        }
        for field in OPTIONAL_FIELDS:
            value = item.get(field)
            if isinstance(value, list):
                normalized[field] = value
        inbox.append(normalized)
        seen.add(key)
        appended += 1

    INBOX.write_text(json.dumps(inbox, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'appended': appended, 'inbox': str(INBOX)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
