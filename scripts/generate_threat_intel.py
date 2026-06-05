#!/usr/bin/env python3
import html
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(os.environ.get('THREAT_INTEL_ROOT', Path(__file__).resolve().parents[1]))
DASHBOARD_DIR = Path(os.environ.get('THREAT_INTEL_DASHBOARD_DIR', ROOT / 'dashboard'))
OUT = Path(os.environ.get('THREAT_INTEL_OUTPUT', DASHBOARD_DIR / 'discoveries-generated.json'))
USER_AGENT = 'cocky-threat-intel/1.0'

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
EPSS_URL = 'https://api.first.org/data/v1/epss'
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

RSS_SOURCES = [
    ('Microsoft Threat Intelligence', 'https://www.microsoft.com/en-us/security/blog/category/cybersecurity/security-intelligence/feed/'),
    ('Palo Alto Unit 42', 'https://unit42.paloaltonetworks.com/feed/'),
    ('Cisco Talos', 'https://blog.talosintelligence.com/rss/'),
    ('The DFIR Report', 'https://thedfirreport.com/feed/'),
    ('Mandiant', [
        'https://www.mandiant.com/resources/blog/rss.xml',
        'https://cloud.google.com/blog/topics/threat-intelligence/rss/',
    ]),
    ('CrowdStrike', 'https://www.crowdstrike.com/en-us/blog/feed/'),
    ('Elastic Security', 'https://www.elastic.co/security-labs/rss/feed.xml'),
    ('Rapid7', 'https://www.rapid7.com/blog/rss/'),
    ('Huntress', 'https://www.huntress.com/blog/rss.xml'),
]

COLLECTION_EVENTS = []

SECURITY_RESEARCH_KEYWORDS = [
    'apt', 'backdoor', 'breach', 'campaign', 'cisa', 'credential',
    'cve', 'cyber', 'detection', 'dfir', 'exploit', 'intrusion',
    'ioc', 'malware', 'phishing', 'ransomware', 'supply chain',
    'threat', 'threat hunting', 'ttp', 'vulnerability', 'zero-day',
]

RESEARCH_EXCLUDE_KEYWORDS = [
    'conference', 'cisco live', 'good boys', 'ironman', 'podcast',
    'webinar', 'hiring', 'award',
]


def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return res.read()


def fetch_json(url, timeout=20):
    return json.loads(fetch(url, timeout).decode('utf-8', errors='replace'))


def record_source(name, kind, status, collected=0, error='', url=''):
    COLLECTION_EVENTS.append({
        'name': name,
        'kind': kind,
        'status': status,
        'collected': int(collected or 0),
        'error': str(error)[:180],
        'url': str(url)[:240],
    })


def today():
    return datetime.now().astimezone().date()


def parse_date(value):
    if not value:
        return None
    value = str(value).strip()
    for fmt in ('%Y-%m-%d', '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(value.replace('Z', ''), fmt).date()
        except ValueError:
            pass
    try:
        return parsedate_to_datetime(value).date()
    except Exception:
        return None


def strip_text(value):
    value = re.sub(r'<[^>]+>', ' ', value or '')
    value = html.unescape(value)
    return re.sub(r'\s+', ' ', value).strip()


def get_epss(cves):
    cves = [c for c in cves if c]
    if not cves:
        return {}
    query = urllib.parse.urlencode({'cve': ','.join(cves[:80])})
    try:
        data = fetch_json(f'{EPSS_URL}?{query}', timeout=20)
    except Exception as exc:
        record_source('FIRST EPSS', 'exploit_probability', 'failed', 0, exc, EPSS_URL)
        return {}
    result = {}
    for item in data.get('data', []):
        try:
            result[item['cve']] = {
                'epss': float(item.get('epss', 0)),
                'percentile': float(item.get('percentile', 0)),
            }
        except Exception:
            continue
    record_source('FIRST EPSS', 'exploit_probability', 'ok', len(result), url=EPSS_URL)
    return result


def get_recent_kev():
    try:
        data = fetch_json(KEV_URL, timeout=25)
    except Exception as exc:
        record_source('CISA KEV', 'vulnerability', 'failed', 0, exc, KEV_URL)
        return []
    cutoff = today() - timedelta(days=21)
    vulns = []
    for item in data.get('vulnerabilities', []):
        date_added = parse_date(item.get('dateAdded'))
        if not date_added or date_added < cutoff:
            continue
        cve = item.get('cveID', '').strip()
        vulns.append({
            'cve': cve,
            'vendor': item.get('vendorProject', ''),
            'product': item.get('product', ''),
            'name': item.get('vulnerabilityName', ''),
            'summary': item.get('shortDescription', ''),
            'date_added': str(date_added),
            'due_date': item.get('dueDate', ''),
            'action': item.get('requiredAction', ''),
            'known_ransomware': item.get('knownRansomwareCampaignUse', ''),
            'source': 'CISA KEV',
            'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        })
    epss = get_epss([v['cve'] for v in vulns])
    for v in vulns:
        v.update(epss.get(v['cve'], {}))
    record_source('CISA KEV', 'vulnerability', 'ok', len(vulns), url=KEV_URL)
    return sorted(vulns, key=lambda x: (x.get('date_added', ''), x.get('epss', 0)), reverse=True)


def cvss_from_metrics(metrics):
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40', 'cvssMetricV2'):
        values = metrics.get(key) or []
        if values:
            cvss = values[0].get('cvssData', {})
            return cvss.get('baseScore'), cvss.get('baseSeverity') or values[0].get('baseSeverity')
    return None, None


def get_recent_nvd():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=2)
    params = urllib.parse.urlencode({
        'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000'),
        'pubEndDate': end.strftime('%Y-%m-%dT%H:%M:%S.999'),
        'resultsPerPage': '80',
    })
    try:
        data = fetch_json(f'{NVD_URL}?{params}', timeout=25)
    except Exception as exc:
        record_source('NVD CVE API 2.0', 'vulnerability', 'failed', 0, exc, NVD_URL)
        return []
    items = []
    for row in data.get('vulnerabilities', []):
        cve = row.get('cve', {})
        score, severity = cvss_from_metrics(cve.get('metrics', {}))
        if score is not None and float(score) < 8.8:
            continue
        cve_id = cve.get('id', '')
        descriptions = cve.get('descriptions', [])
        desc = next((d.get('value') for d in descriptions if d.get('lang') == 'en'), '')
        items.append({
            'cve': cve_id,
            'published': cve.get('published', '')[:10],
            'severity': severity or 'UNKNOWN',
            'cvss': score,
            'summary': strip_text(desc)[:320],
            'source': 'NVD',
            'url': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
        })
    epss = get_epss([v['cve'] for v in items])
    for v in items:
        v.update(epss.get(v['cve'], {}))
    record_source('NVD CVE API 2.0', 'vulnerability', 'ok', len(items), url=NVD_URL)
    return sorted(items, key=lambda x: (x.get('epss', 0), x.get('cvss') or 0), reverse=True)


def source_urls(urls):
    return urls if isinstance(urls, list) else [urls]


def parse_feed_bytes(source, url):
    try:
        raw = fetch(url, timeout=20)
    except Exception as exc:
        return None, exc
    try:
        root = ET.fromstring(raw)
    except Exception as exc:
        return None, exc

    items = []
    channel_items = root.findall('.//item')
    if channel_items:
        for item in channel_items[:12]:
            title = strip_text(item.findtext('title'))
            link = strip_text(item.findtext('link'))
            pub = parse_date(item.findtext('pubDate'))
            desc = strip_text(item.findtext('description'))
            items.append({'source': source, 'title': title, 'url': link, 'date': str(pub or today()), 'summary': desc[:220]})
        return items, None

    ns = {'atom': 'http://www.w3.org/2005/Atom'}
    for item in root.findall('.//atom:entry', ns)[:12]:
        title = strip_text(item.findtext('atom:title', namespaces=ns))
        link_el = item.find('atom:link', ns)
        link = link_el.get('href') if link_el is not None else ''
        pub = parse_date(item.findtext('atom:updated', namespaces=ns) or item.findtext('atom:published', namespaces=ns))
        summary = strip_text(item.findtext('atom:summary', namespaces=ns) or item.findtext('atom:content', namespaces=ns))
        items.append({'source': source, 'title': title, 'url': link, 'date': str(pub or today()), 'summary': summary[:220]})
    return items, None


def parse_feed(source, urls):
    errors = []
    for url in source_urls(urls):
        items, error = parse_feed_bytes(source, url)
        if error is None:
            record_source(source, 'research_feed', 'ok', len(items), url=url)
            return items
        errors.append(f'{url}: {error}')
    record_source(source, 'research_feed', 'failed', 0, '; '.join(errors), source_urls(urls)[0])
    return []


def is_security_research(item):
    haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    if any(term in haystack for term in RESEARCH_EXCLUDE_KEYWORDS):
        return False
    return any(term in haystack for term in SECURITY_RESEARCH_KEYWORDS)


def get_research_watch():
    cutoff = today() - timedelta(days=14)
    items = []
    for source, url in RSS_SOURCES:
        for item in parse_feed(source, url):
            item_date = parse_date(item.get('date')) or today()
            if item_date >= cutoff and is_security_research(item):
                items.append(item)
    items.sort(key=lambda x: x.get('date', ''), reverse=True)
    record_source('Research Filter', 'normalization', 'ok', len(items))
    return items[:10]


def md_table(headers, rows):
    out = ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(['---'] * len(headers)) + ' |']
    out.extend('| ' + ' | '.join(str(c).replace('\n', ' ') for c in row) + ' |' for row in rows)
    return '\n'.join(out)


def priority_for(item):
    if item.get('kev'):
        return 'Critical'
    epss = float(item.get('epss') or 0)
    cvss = float(item.get('cvss') or 0)
    if epss >= 0.20 or cvss >= 9.8:
        return 'High'
    return 'Watch'


def normalize_cve_item(item, source):
    is_kev = source == 'CISA KEV'
    vendor = item.get('vendor', '')
    product = item.get('product', '')
    epss = item.get('epss')
    percentile = item.get('percentile')
    normalized = {
        'cve': item.get('cve', ''),
        'product': f'{vendor} {product}'.strip() if is_kev else item.get('severity', 'UNKNOWN'),
        'vendor': vendor,
        'severity': item.get('severity') or ('KNOWN EXPLOITED' if is_kev else 'UNKNOWN'),
        'cvss': item.get('cvss'),
        'epss': round(float(epss), 4) if epss is not None else None,
        'epss_percentile': round(float(percentile), 4) if percentile is not None else None,
        'kev': is_kev,
        'known_ransomware': item.get('known_ransomware', ''),
        'date': item.get('date_added') or item.get('published') or '',
        'due_date': item.get('due_date', ''),
        'source': source,
        'url': item.get('url', ''),
        'summary': strip_text(item.get('summary') or item.get('name') or '')[:360],
        'recommended_action': item.get('action') or 'Review exposure, patch priority, compensating controls, and detection coverage.',
    }
    normalized['priority'] = priority_for(normalized)
    return normalized


def build_cve_items(kev, nvd):
    items = []
    seen = set()
    for row in kev:
        normalized = normalize_cve_item(row, 'CISA KEV')
        if normalized['cve'] and normalized['cve'] not in seen:
            items.append(normalized)
            seen.add(normalized['cve'])
    for row in nvd:
        normalized = normalize_cve_item(row, 'NVD')
        if normalized['cve'] and normalized['cve'] not in seen:
            items.append(normalized)
            seen.add(normalized['cve'])

    priority_rank = {'Critical': 0, 'High': 1, 'Watch': 2}
    items.sort(key=lambda item: (
        priority_rank.get(item.get('priority'), 9),
        -(float(item.get('epss') or 0)),
        -(float(item.get('cvss') or 0)),
        item.get('date') or '',
    ))
    return items[:14]


def build_action_items(cve_items, research):
    actions = []
    critical = [item for item in cve_items if item.get('priority') == 'Critical']
    high = [item for item in cve_items if item.get('priority') == 'High']

    if critical:
        actions.append({
            'priority': 'Critical',
            'category': 'Exposure Review',
            'task': 'Review assets for CISA KEV matches',
            'reason': f'{len(critical)} known-exploited vulnerabilities were collected today.',
            'owner': 'Security / Infrastructure',
            'due': 'Today',
            'related': [item.get('cve') for item in critical[:6]],
        })

    if high:
        actions.append({
            'priority': 'High',
            'category': 'Patch Queue',
            'task': 'Prioritize high-risk non-KEV CVEs',
            'reason': f'{len(high)} vulnerabilities have high CVSS or EPSS signals.',
            'owner': 'Infrastructure',
            'due': 'This week',
            'related': [item.get('cve') for item in high[:6]],
        })

    if cve_items:
        actions.append({
            'priority': 'High' if critical else 'Watch',
            'category': 'Detection',
            'task': 'Add hunts for products listed in CVE Radar',
            'reason': 'Exploit attempts often appear as abnormal sign-ins, web requests, process creation, or outbound connections before patching is complete.',
            'owner': 'Detection Engineering',
            'due': 'Next review',
            'related': [item.get('cve') for item in cve_items[:6]],
        })

    if research:
        actions.append({
            'priority': 'Watch',
            'category': 'Threat Research',
            'task': 'Extract detection opportunities from recent research posts',
            'reason': f'{len(research[:8])} professional research posts matched the security filter.',
            'owner': 'Security Analyst',
            'due': 'Next review',
            'related': sorted({item.get('source') for item in research[:8] if item.get('source')})[:6],
        })

    if not actions:
        actions.append({
            'priority': 'Watch',
            'category': 'Monitoring',
            'task': 'Continue routine monitoring',
            'reason': 'No high-priority CVE or research signals were collected today.',
            'owner': 'Security Analyst',
            'due': 'Next run',
            'related': [],
        })

    return actions


def build_collection_summary(cve_items, research, action_items):
    aggregated = {}
    for event in COLLECTION_EVENTS:
        key = (event.get('name'), event.get('kind'))
        current = aggregated.setdefault(key, {
            'name': event.get('name'),
            'kind': event.get('kind'),
            'status': 'ok',
            'collected': 0,
            'error': '',
            'url': '',
        })
        current['collected'] += int(event.get('collected') or 0)
        if event.get('url') and not current.get('url'):
            current['url'] = event.get('url')
        if event.get('status') != 'ok':
            current['status'] = event.get('status') or 'failed'
            current['error'] = event.get('error') or current.get('error') or ''
    sources = list(aggregated.values())
    total_sources = len(sources)
    failed_sources = [event for event in sources if event.get('status') != 'ok']
    return {
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'source_count': total_sources,
        'failed_source_count': len(failed_sources),
        'cve_count': len(cve_items),
        'research_count': len(research),
        'action_count': len(action_items),
        'sources': sources,
    }


def build_entries():
    date = str(today())
    kev = get_recent_kev()
    nvd = get_recent_nvd()
    research = get_research_watch()

    cve_items = build_cve_items(kev, nvd)
    action_items = build_action_items(cve_items, research)
    collection = build_collection_summary(cve_items, research, action_items)
    cve_rows = []
    for item in cve_items:
        cve_rows.append([
            item.get('cve'),
            item.get('product') or item.get('severity', 'UNKNOWN'),
            item.get('priority'),
            'KEV' if item.get('kev') else item.get('severity', 'UNKNOWN'),
            f"{item.get('epss'):.3f}" if item.get('epss') is not None else '-',
            item.get('date'),
        ])
    cve_content = [
        '## Daily Assessment',
        'Prioritize vulnerabilities that are listed in CISA KEV, have elevated EPSS probability, or were recently published by NVD with high severity. KEV indicates known exploitation and should be treated as a patching or mitigation priority.',
        '',
        '## CVE Radar',
        md_table(['CVE', 'Product / Severity', 'Priority', 'Signal', 'EPSS', 'Date'], cve_rows[:12]) if cve_rows else 'No high-priority CVE signals were collected today.',
        '',
        '## Defender Guidance',
        '- Check internet-facing assets, VPNs, firewalls, identity systems, and common open-source components against the CVE table.',
        '- Treat KEV matches as urgent remediation items; CVSS-only findings without exploitation signals can stay in the standard patch queue.',
        '- For affected products, add log hunts for abnormal sign-ins, web exploit traces, suspicious process creation, and unusual outbound connections.',
        '',
        '## Sources',
        '- CISA Known Exploited Vulnerabilities Catalog',
        '- NVD CVE API 2.0',
        '- FIRST EPSS API',
    ]

    research_lines = ['## Professional Security Research Watch']
    if research:
        for item in research[:8]:
            research_lines.append(f"- **{item['source']}** ({item['date']}): [{item['title']}]({item['url']})")
            if item.get('summary'):
                research_lines.append(f"  - {item['summary']}")
    else:
        research_lines.append('No matching professional security research posts were collected today.')
    research_lines.extend([
        '',
        '## Why It Matters',
        'These sources come from professional security research teams and are closer to attack chains, TTPs, exploitation details, and detection guidance than general technology news.',
        '',
        '## Sources',
        '- Microsoft Threat Intelligence',
        '- Palo Alto Unit 42',
        '- Cisco Talos',
        '- The DFIR Report',
        '- Mandiant',
        '- CrowdStrike',
        '- Elastic Security',
        '- Rapid7',
        '- Huntress',
    ])

    action_lines = ['## Daily Defender Checklist']
    for index, item in enumerate(action_items, 1):
        related = ', '.join(item.get('related') or [])
        suffix = f" Related: {related}." if related else ''
        action_lines.append(f"{index}. **{item['task']}** [{item['priority']} / {item['category']}]. {item['reason']}{suffix}")
    action_lines.extend([
        '',
        '## Output Boundary',
        'This entry is generated by a deterministic script. The scheduler or agent should only run the script and forward its output.',
    ])

    return [
        {
            'kind': 'cve_radar',
            'date': date,
            'title': f'CVE Radar - {date}',
            'content': '\n'.join(cve_content),
            'items': cve_items,
            'sources': ['CISA KEV', 'NVD CVE API 2.0', 'FIRST EPSS API'],
            'collection': collection,
        },
        {
            'kind': 'threat_intel',
            'date': date,
            'title': f'Professional Security Research Watch - {date}',
            'content': '\n'.join(research_lines),
            'items': research[:8],
            'sources': [source for source, _ in RSS_SOURCES],
            'collection': collection,
        },
        {
            'kind': 'defender_actions',
            'date': date,
            'title': f'Defender Action Checklist - {date}',
            'content': '\n'.join(action_lines),
            'items': action_items,
            'collection': collection,
        },
    ]


def main():
    entries = build_entries()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(entries, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(entries, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'generate_threat_intel failed: {exc}', file=sys.stderr)
        raise
