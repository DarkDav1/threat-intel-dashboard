#!/usr/bin/env python3
import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ.get('THREAT_INTEL_ROOT', Path(__file__).resolve().parents[1]))
DASHBOARD_DIR = Path(os.environ.get('THREAT_INTEL_DASHBOARD_DIR', ROOT / 'dashboard'))
DISCOVERIES = Path(os.environ.get('THREAT_INTEL_DISCOVERIES', DASHBOARD_DIR / 'discoveries.json'))
OUT = Path(os.environ.get('THREAT_INTEL_BRIEFING', DASHBOARD_DIR / 'daily-briefing.md'))


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return default


def latest(entries):
    if not isinstance(entries, list):
        return {}
    valid = [entry for entry in entries if isinstance(entry, dict)]
    return sorted(valid, key=lambda entry: str(entry.get('date', '')), reverse=True)[0] if valid else {}


def items(entry):
    value = entry.get('items') if isinstance(entry, dict) else []
    return value if isinstance(value, list) else []


def text(value, fallback='-'):
    if value is None or value == '':
        return fallback
    return str(value).replace('\n', ' ').strip()


def table(headers, rows):
    def cell(value):
        return text(value).replace('|', '\\|')
    out = ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(['---'] * len(headers)) + ' |']
    out.extend('| ' + ' | '.join(cell(value) for value in row) + ' |' for row in rows)
    return '\n'.join(out)


def pct(value):
    if value is None:
        return '-'
    try:
        return f'{float(value) * 100:.1f}%'
    except Exception:
        return '-'


def top_watchlist_groups(cve_items):
    counts = {}
    for item in cve_items:
        for match in item.get('watchlist_matches') or []:
            group = match.get('group')
            if group:
                counts[group] = counts.get(group, 0) + 1
    return sorted(counts.items(), key=lambda row: (-row[1], row[0]))


def build_briefing(data):
    cve_entry = latest(data.get('cve_radar', {}).get('entries', []))
    research_entry = latest(data.get('threat_intel', {}).get('entries', []))
    actions_entry = latest(data.get('defender_actions', {}).get('entries', []))
    cves = items(cve_entry)
    research = items(research_entry)
    actions = items(actions_entry)
    collection = cve_entry.get('collection') or research_entry.get('collection') or actions_entry.get('collection') or {}
    watchlist = collection.get('watchlist') or {}
    date = cve_entry.get('date') or research_entry.get('date') or datetime.now(timezone.utc).date().isoformat()
    generated_at = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    critical = [item for item in cves if item.get('priority') == 'Critical']
    high = [item for item in cves if item.get('priority') == 'High']
    watchlist_cves = [item for item in cves if int(item.get('relevance_score') or 0) > 0]
    failed_sources = collection.get('failed_source_count', 0)

    lines = [
        f'# Threat Intelligence Briefing - {date}',
        '',
        f'Generated at: `{generated_at}`',
        '',
        '## Executive Summary',
        '',
        f'- CVE signals: **{len(cves)}**',
        f'- Critical CVEs: **{len(critical)}**',
        f'- High CVEs: **{len(high)}**',
        f'- Watchlist-matched CVEs: **{len(watchlist_cves)}**',
        f'- Research posts: **{len(research)}**',
        f'- Source failures: **{failed_sources}**',
        f'- Watchlist profile: **{text(watchlist.get("profile"), "None")}**',
        '',
    ]

    if failed_sources:
        lines.extend([
            '## Collection Warning',
            '',
            f'{failed_sources} source(s) failed during the latest collection run. Check the Pipeline tab before treating the briefing as complete.',
            '',
        ])

    top_cves = sorted(cves, key=lambda item: (int(item.get('risk_score') or 0), int(item.get('relevance_score') or 0)), reverse=True)[:8]
    lines.extend([
        '## Top Vulnerabilities',
        '',
        table(
            ['CVE', 'Priority', 'Risk', 'Relevance', 'Impact Area', 'Signal', 'EPSS', 'Action'],
            [
                [
                    item.get('cve'),
                    item.get('priority'),
                    item.get('risk_score', 0),
                    item.get('relevance_score', 0),
                    item.get('impact_area'),
                    'CISA KEV' if item.get('kev') else item.get('source'),
                    pct(item.get('epss')),
                    item.get('recommended_action'),
                ]
                for item in top_cves
            ],
        ) if top_cves else 'No CVE signals were collected.',
        '',
    ])

    groups = top_watchlist_groups(cves)
    lines.extend([
        '## Local Relevance',
        '',
        table(['Watchlist Group', 'Matched CVEs'], groups[:6]) if groups else 'No CVE matched the local watchlist.',
        '',
    ])

    lines.extend([
        '## Defender Actions',
        '',
    ])
    if actions:
        for index, action in enumerate(actions[:8], 1):
            related = ', '.join(str(value) for value in action.get('related', [])[:8])
            related_suffix = f' Related: {related}.' if related else ''
            lines.append(f'{index}. **{text(action.get("task"))}** [{text(action.get("priority"))} / {text(action.get("category"))}] - {text(action.get("reason"))}{related_suffix}')
    else:
        lines.append('No defender action items were generated.')
    lines.append('')

    lines.extend([
        '## Research Watch',
        '',
    ])
    if research:
        lines.append(table(
            ['Date', 'Source', 'Category', 'Relevance', 'Title'],
            [
                [
                    item.get('date'),
                    item.get('source'),
                    item.get('category'),
                    item.get('relevance_score', 0),
                    item.get('title'),
                ]
                for item in research[:8]
            ],
        ))
    else:
        lines.append('No research posts matched the security filter.')
    lines.append('')

    sources = collection.get('sources') if isinstance(collection.get('sources'), list) else []
    lines.extend([
        '## Source Coverage',
        '',
        table(
            ['Status', 'Source', 'Kind', 'Collected'],
            [[source.get('status'), source.get('name'), source.get('kind'), source.get('collected')] for source in sources],
        ) if sources else 'No source coverage data was recorded.',
        '',
        '## Notes',
        '',
        '- This briefing is generated from validated dashboard data after append and merge complete.',
        '- It is a triage aid, not a replacement for vendor advisories or asset-owner validation.',
        '',
    ])

    return '\n'.join(lines)


def main():
    data = load_json(DISCOVERIES, {})
    if not isinstance(data, dict):
        raise SystemExit('discoveries.json must be a JSON object')
    OUT.parent.mkdir(parents=True, exist_ok=True)
    briefing = build_briefing(data)
    OUT.write_text(briefing + '\n', encoding='utf-8')
    print(json.dumps({'briefing': str(OUT), 'bytes': OUT.stat().st_size}, ensure_ascii=False))


if __name__ == '__main__':
    main()
