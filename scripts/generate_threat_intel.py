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
WATCHLIST_PATH = Path(os.environ.get('THREAT_INTEL_WATCHLIST', ROOT / 'config' / 'watchlist.json'))
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

IMPACT_RULES = [
    ('Network Edge', ['vpn', 'firewall', 'gateway', 'router', 'fortinet', 'fortigate', 'palo alto', 'netscaler', 'citrix adc', 'f5', 'ivanti', 'sonicwall']),
    ('Identity', ['active directory', 'entra', 'azure ad', 'ldap', 'saml', 'oauth', 'identity', 'credential', 'authentication']),
    ('Windows', ['microsoft windows', 'windows server', 'exchange', 'sharepoint', 'office', 'outlook', 'internet explorer', 'edge']),
    ('Linux / Unix', ['linux', 'ubuntu', 'debian', 'red hat', 'rhel', 'kernel', 'sudo', 'openssh', 'unix']),
    ('Cloud / Container', ['aws', 'azure', 'gcp', 'cloud', 'kubernetes', 'docker', 'container', 'helm', 'terraform']),
    ('Developer Tooling', ['github', 'gitlab', 'jenkins', 'ci/cd', 'pipeline', 'build', 'npm', 'pypi', 'maven']),
    ('Application Server', ['apache', 'nginx', 'tomcat', 'weblogic', 'jboss', 'iis', 'struts', 'spring']),
    ('Database', ['postgres', 'mysql', 'mssql', 'oracle database', 'mongodb', 'redis', 'elasticsearch']),
    ('Browser / Endpoint', ['browser', 'chrome', 'firefox', 'safari', 'endpoint', 'edr', 'adobe', 'acrobat']),
]

EXPLOIT_KEYWORDS = ['remote code execution', 'execute arbitrary code', 'rce', 'command injection', 'deserialization']
AUTH_BYPASS_KEYWORDS = ['authentication bypass', 'auth bypass', 'privilege escalation', 'elevation of privilege']
PUBLIC_EXPOSURE_KEYWORDS = ['internet-facing', 'remote attacker', 'network', 'crafted request', 'web request']

DETECTION_BASELINES = {
    'Windows': {
        'log_sources': ['Windows Event Log', 'EDR process telemetry', 'PowerShell logs', 'Network connections'],
        'hunt_ideas': ['Look for service crashes followed by unexpected child processes', 'Review suspicious network service activity and outbound connections'],
        'mitre': ['T1059 Command and Scripting Interpreter', 'T1203 Exploitation for Client Execution'],
    },
    'Network Edge': {
        'log_sources': ['VPN logs', 'Firewall traffic logs', 'Reverse proxy logs', 'Authentication logs'],
        'hunt_ideas': ['Review unusual admin logins from new geographies', 'Search for exploit-like HTTP requests and config changes'],
        'mitre': ['T1190 Exploit Public-Facing Application', 'T1133 External Remote Services'],
    },
    'Identity': {
        'log_sources': ['Identity provider sign-in logs', 'Directory audit logs', 'MFA events', 'EDR authentication telemetry'],
        'hunt_ideas': ['Review impossible travel, MFA fatigue, and new privileged role assignments', 'Search for abnormal LDAP, SAML, or OAuth activity'],
        'mitre': ['T1078 Valid Accounts', 'T1556 Modify Authentication Process'],
    },
    'Linux / Unix': {
        'log_sources': ['syslog', 'auth.log', 'auditd', 'EDR process telemetry'],
        'hunt_ideas': ['Look for shell execution by service users', 'Review new cron jobs, SSH keys, and unusual outbound traffic'],
        'mitre': ['T1059 Command and Scripting Interpreter', 'T1068 Exploitation for Privilege Escalation'],
    },
    'Cloud / Container': {
        'log_sources': ['Cloud audit logs', 'Kubernetes audit logs', 'Container runtime logs', 'CI/CD logs'],
        'hunt_ideas': ['Review new service accounts, secrets access, and privileged containers', 'Search for unexpected image pulls or workload changes'],
        'mitre': ['T1611 Escape to Host', 'T1525 Implant Internal Image'],
    },
    'Developer Tooling': {
        'log_sources': ['CI/CD job logs', 'Git audit logs', 'Package registry logs', 'Build artifact records'],
        'hunt_ideas': ['Review new pipeline secrets, package publish events, and unexpected dependency changes', 'Search for suspicious build scripts or post-install commands'],
        'mitre': ['T1195 Supply Chain Compromise', 'T1552 Unsecured Credentials'],
    },
    'Application Server': {
        'log_sources': ['Web access logs', 'Application logs', 'WAF logs', 'EDR process telemetry'],
        'hunt_ideas': ['Search for exploit payloads in HTTP parameters and unusual server child processes', 'Review webshell indicators and outbound callbacks'],
        'mitre': ['T1190 Exploit Public-Facing Application', 'T1505 Server Software Component'],
    },
    'Database': {
        'log_sources': ['Database audit logs', 'Authentication logs', 'Network flow logs', 'EDR process telemetry'],
        'hunt_ideas': ['Review failed logins, new admin users, and bulk export activity', 'Search for database processes spawning shells or network tools'],
        'mitre': ['T1005 Data from Local System', 'T1041 Exfiltration Over C2 Channel'],
    },
    'Browser / Endpoint': {
        'log_sources': ['EDR process telemetry', 'Browser crash logs', 'Proxy logs', 'DNS logs'],
        'hunt_ideas': ['Look for browser processes spawning script interpreters or archive tools', 'Review downloads followed by suspicious process trees'],
        'mitre': ['T1203 Exploitation for Client Execution', 'T1059 Command and Scripting Interpreter'],
    },
    'General Software': {
        'log_sources': ['Application logs', 'EDR process telemetry', 'Network flow logs'],
        'hunt_ideas': ['Review abnormal process starts, crashes, and outbound connections around exposed services'],
        'mitre': ['T1190 Exploit Public-Facing Application'],
    },
}

RESEARCH_CATEGORY_RULES = [
    ('Active Exploitation', ['active exploitation', 'exploited in the wild', 'zero-day', 'kev', 'intrusion', 'campaign']),
    ('Malware / Ransomware', ['malware', 'ransomware', 'backdoor', 'loader', 'botnet', 'trojan']),
    ('Detection Engineering', ['detection', 'hunt', 'hunting', 'sigma', 'yara', 'telemetry', 'ioc']),
    ('Cloud / Identity', ['cloud', 'identity', 'azure', 'aws', 'gcp', 'entra', 'oauth', 'saml']),
    ('Vulnerability Research', ['cve', 'vulnerability', 'exploit', 'patch', 'remote code execution']),
    ('Incident Response', ['dfir', 'incident', 'forensic', 'breach', 'response']),
]

RESEARCH_EXCLUDE_KEYWORDS = [
    'conference', 'cisco live', 'good boys', 'ironman', 'podcast',
    'webinar', 'hiring', 'award',
]

DEFAULT_WATCHLIST = {
    'profile': 'Default security operations profile',
    'description': 'Fallback local relevance profile used when config/watchlist.json is not present.',
    'groups': [
        {'name': 'Windows and Identity', 'weight': 14, 'keywords': ['microsoft', 'windows', 'exchange', 'sharepoint', 'active directory', 'entra']},
        {'name': 'Network Edge', 'weight': 12, 'keywords': ['vpn', 'firewall', 'router', 'gateway', 'fortinet', 'palo alto', 'ivanti']},
        {'name': 'Linux and Self-hosted Services', 'weight': 10, 'keywords': ['linux', 'openssh', 'nginx', 'apache', 'docker', 'kubernetes', 'postgres']},
        {'name': 'Developer and CI/CD', 'weight': 8, 'keywords': ['github', 'gitlab', 'jenkins', 'ci/cd', 'pipeline', 'supply chain']},
        {'name': 'Detection and Response', 'weight': 6, 'keywords': ['detection', 'threat hunting', 'dfir', 'incident response', 'ioc', 'ransomware']},
    ],
}


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


def normalize_watchlist(data):
    if not isinstance(data, dict):
        data = DEFAULT_WATCHLIST
    groups = []
    for group in data.get('groups', []):
        if not isinstance(group, dict):
            continue
        name = strip_text(str(group.get('name') or '')).strip()
        keywords = [
            strip_text(str(keyword)).lower()
            for keyword in group.get('keywords', [])
            if isinstance(keyword, str) and strip_text(keyword)
        ]
        if not name or not keywords:
            continue
        try:
            weight = int(group.get('weight', 6))
        except Exception:
            weight = 6
        groups.append({
            'name': name,
            'weight': max(1, min(weight, 20)),
            'keywords': sorted(set(keywords)),
        })
    if not groups:
        return normalize_watchlist(DEFAULT_WATCHLIST)
    return {
        'profile': strip_text(str(data.get('profile') or DEFAULT_WATCHLIST['profile']))[:80],
        'description': strip_text(str(data.get('description') or ''))[:220],
        'groups': groups,
    }


def load_watchlist():
    try:
        data = json.loads(WATCHLIST_PATH.read_text(encoding='utf-8'))
    except Exception:
        data = DEFAULT_WATCHLIST
    return normalize_watchlist(data)


def watchlist_text(item):
    values = []
    for key in ('cve', 'vendor', 'product', 'name', 'title', 'summary', 'severity', 'source', 'category', 'impact_area'):
        values.append(str(item.get(key, '')))
    if isinstance(item.get('risk_factors'), list):
        values.extend(str(value) for value in item.get('risk_factors'))
    return ' '.join(values).lower()


def match_watchlist(item, watchlist):
    haystack = watchlist_text(item)
    matches = []
    for group in watchlist.get('groups', []):
        matched = [keyword for keyword in group.get('keywords', []) if keyword in haystack]
        if matched:
            matches.append({
                'group': group.get('name', 'Watchlist'),
                'weight': int(group.get('weight') or 1),
                'keywords': matched[:5],
            })
    matches.sort(key=lambda value: (-int(value.get('weight') or 0), value.get('group') or ''))
    return matches


def relevance_score(matches):
    return min(25, sum(int(match.get('weight') or 0) for match in matches[:3]))


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


def classify_research(item):
    haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    for category, keywords in RESEARCH_CATEGORY_RULES:
        if any(keyword in haystack for keyword in keywords):
            return category
    return 'Threat Research'


def get_research_watch(watchlist):
    cutoff = today() - timedelta(days=14)
    items = []
    for source, url in RSS_SOURCES:
        for item in parse_feed(source, url):
            item_date = parse_date(item.get('date')) or today()
            if item_date >= cutoff and is_security_research(item):
                item['category'] = classify_research(item)
                matches = match_watchlist(item, watchlist)
                item['watchlist_matches'] = matches
                item['relevance_score'] = relevance_score(matches)
                items.append(item)
    items.sort(key=lambda x: (int(x.get('relevance_score') or 0), x.get('date', '')), reverse=True)
    record_source('Research Filter', 'normalization', 'ok', len(items))
    return items[:10]


def md_table(headers, rows):
    out = ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(['---'] * len(headers)) + ' |']
    out.extend('| ' + ' | '.join(str(c).replace('\n', ' ') for c in row) + ' |' for row in rows)
    return '\n'.join(out)


def priority_for(item):
    if item.get('kev') or int(item.get('risk_score') or 0) >= 85:
        return 'Critical'
    if int(item.get('risk_score') or 0) >= 70:
        return 'High'
    epss = float(item.get('epss') or 0)
    cvss = float(item.get('cvss') or 0)
    if epss >= 0.20 or cvss >= 9.8:
        return 'High'
    return 'Watch'


def infer_impact_area(item):
    text = ' '.join(str(item.get(key, '')) for key in ('vendor', 'product', 'name', 'summary', 'severity')).lower()
    for area, keywords in IMPACT_RULES:
        if any(keyword in text for keyword in keywords):
            return area
    return 'General Software'


def infer_product_context(item, is_kev):
    if is_kev:
        return f"{item.get('vendor', '')} {item.get('product', '')}".strip()
    summary = item.get('summary', '')
    for pattern in (
        r'^(.*?) contains? ',
        r'^(.*?) allows? ',
        r'^(.*?) before ',
        r'^(.*?) versions? ',
    ):
        match = re.search(pattern, summary, flags=re.I)
        if match:
            value = strip_text(match.group(1)).strip(' .,:;')
            if 3 <= len(value) <= 90:
                return value
    return item.get('severity', 'UNKNOWN')


def calculate_risk(item, is_kev):
    score = 0
    factors = []
    cvss = float(item.get('cvss') or 0)
    epss = float(item.get('epss') or 0)
    percentile = float(item.get('percentile') or 0)
    summary = strip_text(item.get('summary') or item.get('name') or '').lower()

    if is_kev:
        score += 45
        factors.append('CISA KEV')
    if cvss >= 9.8:
        score += 22
        factors.append('CVSS critical')
    elif cvss >= 8.8:
        score += 15
        factors.append('CVSS high')
    if epss >= 0.50:
        score += 22
        factors.append('EPSS very high')
    elif epss >= 0.20:
        score += 16
        factors.append('EPSS elevated')
    elif percentile >= 0.95:
        score += 12
        factors.append('EPSS top percentile')
    if str(item.get('known_ransomware', '')).lower() == 'known':
        score += 10
        factors.append('Ransomware linked')
    if any(term in summary for term in EXPLOIT_KEYWORDS):
        score += 10
        factors.append('Code execution')
    if any(term in summary for term in AUTH_BYPASS_KEYWORDS):
        score += 8
        factors.append('Auth or privilege impact')
    if any(term in summary for term in PUBLIC_EXPOSURE_KEYWORDS):
        score += 6
        factors.append('Remote attack surface')

    return min(score, 100), factors or ['Review required']


def detection_guidance(item):
    area = item.get('impact_area') or 'General Software'
    base = DETECTION_BASELINES.get(area, DETECTION_BASELINES['General Software'])
    summary = strip_text(item.get('summary') or '').lower()
    hints = {
        'log_sources': list(base['log_sources']),
        'hunt_ideas': list(base['hunt_ideas']),
        'mitre': list(base['mitre']),
    }
    if any(term in summary for term in EXPLOIT_KEYWORDS):
        hints['hunt_ideas'].append('Prioritize process trees that begin immediately after exploit-facing service activity')
        hints['mitre'].append('T1059 Command and Scripting Interpreter')
    if any(term in summary for term in AUTH_BYPASS_KEYWORDS):
        hints['log_sources'].append('Privilege and role-change audit logs')
        hints['hunt_ideas'].append('Review new privileged sessions, token use, and account changes after suspicious access')
        hints['mitre'].append('T1068 Exploitation for Privilege Escalation')
    if any(term in summary for term in PUBLIC_EXPOSURE_KEYWORDS) or item.get('kev'):
        hints['log_sources'].append('Internet-facing service logs')
        hints['hunt_ideas'].append('Search perimeter logs for repeated exploit attempts against affected products')
        hints['mitre'].append('T1190 Exploit Public-Facing Application')

    for key in hints:
        seen = []
        for value in hints[key]:
            if value not in seen:
                seen.append(value)
        hints[key] = seen[:5]
    return hints


def normalize_cve_item(item, source, watchlist):
    is_kev = source == 'CISA KEV'
    vendor = item.get('vendor', '')
    epss = item.get('epss')
    percentile = item.get('percentile')
    summary = strip_text(item.get('summary') or item.get('name') or '')[:360]
    base_risk_score, risk_factors = calculate_risk(item, is_kev)
    normalized = {
        'cve': item.get('cve', ''),
        'product': infer_product_context({**item, 'summary': summary}, is_kev),
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
        'summary': summary,
        'recommended_action': item.get('action') or 'Review exposure, patch priority, compensating controls, and detection coverage.',
        'base_risk_score': base_risk_score,
        'risk_factors': risk_factors,
    }
    normalized['impact_area'] = infer_impact_area({**item, **normalized})
    normalized['detection'] = detection_guidance(normalized)
    matches = match_watchlist({**item, **normalized}, watchlist)
    normalized['watchlist_matches'] = matches
    normalized['relevance_score'] = relevance_score(matches)
    normalized['risk_score'] = min(100, base_risk_score + normalized['relevance_score'])
    if normalized['relevance_score']:
        normalized['risk_factors'] = risk_factors + ['Local relevance']
    normalized['priority'] = priority_for(normalized)
    return normalized


def build_cve_items(kev, nvd, watchlist):
    items = []
    seen = set()
    for row in kev:
        normalized = normalize_cve_item(row, 'CISA KEV', watchlist)
        if normalized['cve'] and normalized['cve'] not in seen:
            items.append(normalized)
            seen.add(normalized['cve'])
    for row in nvd:
        normalized = normalize_cve_item(row, 'NVD', watchlist)
        if normalized['cve'] and normalized['cve'] not in seen:
            items.append(normalized)
            seen.add(normalized['cve'])

    priority_rank = {'Critical': 0, 'High': 1, 'Watch': 2}
    items.sort(key=lambda item: (
        priority_rank.get(item.get('priority'), 9),
        -(int(item.get('risk_score') or 0)),
        -(float(item.get('epss') or 0)),
        -(float(item.get('cvss') or 0)),
        item.get('date') or '',
    ))
    return items[:14]


def build_action_items(cve_items, research, watchlist):
    actions = []
    critical = [item for item in cve_items if item.get('priority') == 'Critical']
    high = [item for item in cve_items if item.get('priority') == 'High']
    relevant = [item for item in cve_items if int(item.get('relevance_score') or 0) > 0]
    impact_counts = {}
    for item in cve_items:
        area = item.get('impact_area') or 'General Software'
        impact_counts[area] = impact_counts.get(area, 0) + 1
    top_areas = sorted(impact_counts, key=lambda area: (-impact_counts[area], area))[:3]

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

    if top_areas:
        actions.append({
            'priority': 'High' if critical or high else 'Watch',
            'category': 'Asset Mapping',
            'task': 'Map CVE exposure by affected technology area',
            'reason': 'Daily CVE signals cluster around: ' + ', '.join(f'{area} ({impact_counts[area]})' for area in top_areas) + '.',
            'owner': 'Security / Asset Owner',
            'due': 'Today' if critical else 'Next review',
            'related': top_areas,
        })

    if relevant:
        groups = {}
        for item in relevant:
            for match in item.get('watchlist_matches') or []:
                group = match.get('group')
                if group:
                    groups[group] = groups.get(group, 0) + 1
        top_groups = sorted(groups, key=lambda group: (-groups[group], group))[:3]
        actions.append({
            'priority': 'Critical' if critical else 'High',
            'category': 'Local Relevance',
            'task': 'Prioritize CVEs that match the local watchlist',
            'reason': f'{len(relevant)} CVE signals match the {watchlist.get("profile", "local")} watchlist: ' + ', '.join(f'{group} ({groups[group]})' for group in top_groups) + '.',
            'owner': 'Security / Asset Owner',
            'due': 'Today',
            'related': [item.get('cve') for item in relevant[:6]],
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
        top_log_sources = []
        for item in cve_items[:8]:
            for source in (item.get('detection') or {}).get('log_sources') or []:
                if source not in top_log_sources:
                    top_log_sources.append(source)
        actions.append({
            'priority': 'High' if critical else 'Watch',
            'category': 'Detection',
            'task': 'Add hunts for products listed in CVE Radar',
            'reason': 'Exploit attempts often appear before patching is complete. Prioritize telemetry from: ' + ', '.join(top_log_sources[:5]) + '.',
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


def build_collection_summary(cve_items, research, action_items, watchlist):
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
        'watchlist': {
            'profile': watchlist.get('profile', 'Local watchlist'),
            'description': watchlist.get('description', ''),
            'group_count': len(watchlist.get('groups', [])),
            'matched_cve_count': len([item for item in cve_items if int(item.get('relevance_score') or 0) > 0]),
            'matched_research_count': len([item for item in research if int(item.get('relevance_score') or 0) > 0]),
            'groups': [
                {'name': group.get('name'), 'weight': group.get('weight'), 'keyword_count': len(group.get('keywords', []))}
                for group in watchlist.get('groups', [])
            ],
        },
        'sources': sources,
    }


def build_entries():
    date = str(today())
    watchlist = load_watchlist()
    kev = get_recent_kev()
    nvd = get_recent_nvd()
    research = get_research_watch(watchlist)

    cve_items = build_cve_items(kev, nvd, watchlist)
    action_items = build_action_items(cve_items, research, watchlist)
    collection = build_collection_summary(cve_items, research, action_items, watchlist)
    cve_rows = []
    for item in cve_items:
        watchlist_groups = ', '.join(match.get('group', '') for match in (item.get('watchlist_matches') or [])[:2]) or '-'
        cve_rows.append([
            item.get('cve'),
            item.get('product') or item.get('severity', 'UNKNOWN'),
            item.get('priority'),
            item.get('risk_score', 0),
            item.get('relevance_score', 0),
            watchlist_groups,
            item.get('impact_area', 'General Software'),
            'KEV' if item.get('kev') else item.get('severity', 'UNKNOWN'),
            f"{item.get('epss'):.3f}" if item.get('epss') is not None else '-',
            item.get('date'),
        ])
    cve_content = [
        '## Daily Assessment',
        'Prioritize vulnerabilities that are listed in CISA KEV, have elevated EPSS probability, or were recently published by NVD with high severity. KEV indicates known exploitation and should be treated as a patching or mitigation priority.',
        '',
        '## CVE Radar',
        md_table(['CVE', 'Product / Severity', 'Priority', 'Risk', 'Relevance', 'Watchlist', 'Impact Area', 'Signal', 'EPSS', 'Date'], cve_rows[:12]) if cve_rows else 'No high-priority CVE signals were collected today.',
        '',
        '## Local Relevance Profile',
        f"Profile: {watchlist.get('profile', 'Local watchlist')}. Matched CVEs: {collection['watchlist']['matched_cve_count']}. Matched research posts: {collection['watchlist']['matched_research_count']}.",
        '',
        '## Defender Guidance',
        '- Check internet-facing assets, VPNs, firewalls, identity systems, and common open-source components against the CVE table.',
        '- Treat KEV matches as urgent remediation items; CVSS-only findings without exploitation signals can stay in the standard patch queue.',
        '- For affected products, add log hunts for abnormal sign-ins, web exploit traces, suspicious process creation, and unusual outbound connections.',
        '- Use the detection guidance fields to map high-risk CVEs to log sources, hunt ideas, and ATT&CK techniques.',
        '',
        '## Sources',
        '- CISA Known Exploited Vulnerabilities Catalog',
        '- NVD CVE API 2.0',
        '- FIRST EPSS API',
    ]

    research_lines = ['## Professional Security Research Watch']
    if research:
        for item in research[:8]:
            relevance = f" relevance {item.get('relevance_score', 0)}" if item.get('relevance_score') else ''
            research_lines.append(f"- **{item['source']}** ({item['date']} / {item.get('category', 'Threat Research')}{relevance}): [{item['title']}]({item['url']})")
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
