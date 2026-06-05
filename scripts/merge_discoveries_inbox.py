#!/usr/bin/env python3
import json
import os
import shutil
from pathlib import Path

ROOT = Path(os.environ.get('THREAT_INTEL_ROOT', Path(__file__).resolve().parents[1]))
DASHBOARD_DIR = Path(os.environ.get('THREAT_INTEL_DASHBOARD_DIR', ROOT / 'dashboard'))
DISCOVERIES = Path(os.environ.get('THREAT_INTEL_DISCOVERIES', DASHBOARD_DIR / 'discoveries.json'))
INBOX = Path(os.environ.get('THREAT_INTEL_INBOX', DASHBOARD_DIR / 'discoveries-inbox.json'))
BACKUP = Path(os.environ.get('THREAT_INTEL_BACKUP', DASHBOARD_DIR / 'discoveries.json.bak'))
ALLOWED_KINDS = {
    'threat_intel', 'cve_radar', 'defender_actions'
}
OPTIONAL_FIELDS = {'items', 'sources'}


def keep_optional_fields(item):
    kept = {}
    for field in OPTIONAL_FIELDS:
        value = item.get(field)
        if isinstance(value, list):
            kept[field] = value
    return kept


def load_json(path, default):
    if not path.exists():
        return default
    text = path.read_text(encoding='utf-8').strip()
    if not text:
        return default
    return json.loads(text)


def main():
    discoveries = load_json(DISCOVERIES, {})
    inbox = load_json(INBOX, [])

    if not isinstance(discoveries, dict):
        raise SystemExit('discoveries.json must be a JSON object')
    if not isinstance(inbox, list):
        raise SystemExit('discoveries-inbox.json must be a JSON array')

    valid = []
    rejected = []
    for item in inbox:
        if not isinstance(item, dict):
            rejected.append({'item': item, 'reason': 'not-object'})
            continue
        kind = item.get('kind')
        date = item.get('date')
        title = item.get('title')
        content = item.get('content')
        if kind not in ALLOWED_KINDS:
            rejected.append({'item': item, 'reason': 'bad-kind'})
            continue
        if not all(isinstance(x, str) and x.strip() for x in [kind, date, title, content]):
            rejected.append({'item': item, 'reason': 'missing-fields'})
            continue
        normalized = {
            'kind': kind,
            'date': date.strip(),
            'title': title.strip(),
            'content': content.strip(),
        }
        normalized.update(keep_optional_fields(item))
        valid.append(normalized)

    for kind in ALLOWED_KINDS:
        if kind in discoveries and not isinstance(discoveries[kind], dict):
            raise SystemExit(f'discoveries[{kind}] must be object')
        if kind in discoveries and 'entries' in discoveries[kind] and not isinstance(discoveries[kind]['entries'], list):
            raise SystemExit(f'discoveries[{kind}].entries must be array')

    merged_count = 0
    updated_count = 0
    for item in valid:
        bucket = discoveries.setdefault(item['kind'], {'entries': []})
        entries = bucket.setdefault('entries', [])
        key = (item['date'], item['title'])
        existing = next((e for e in entries if isinstance(e, dict) and (e.get('date'), e.get('title')) == key), None)
        if existing:
            changed = existing.get('content') != item['content']
            existing['content'] = item['content']
            for field in OPTIONAL_FIELDS:
                if field in item:
                    changed = changed or existing.get(field) != item[field]
                    existing[field] = item[field]
                elif field in existing:
                    changed = True
                    existing.pop(field, None)
            if changed:
                updated_count += 1
            continue
        new_entry = {
            'date': item['date'],
            'title': item['title'],
            'content': item['content'],
        }
        new_entry.update(keep_optional_fields(item))
        entries.insert(0, new_entry)
        merged_count += 1

    if DISCOVERIES.exists():
        shutil.copy2(DISCOVERIES, BACKUP)
    DISCOVERIES.write_text(json.dumps(discoveries, ensure_ascii=False, indent=2), encoding='utf-8')
    INBOX.write_text('[]\n', encoding='utf-8')

    summary = {
        'merged': merged_count,
        'updated': updated_count,
        'valid_inbox_items': len(valid),
        'rejected': rejected,
        'backup': str(BACKUP),
        'discoveries': str(DISCOVERIES),
        'inbox_cleared': True,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
