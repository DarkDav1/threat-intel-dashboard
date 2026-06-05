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
]

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
    except Exception:
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
    return result


def get_recent_kev():
    data = fetch_json(KEV_URL, timeout=25)
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
            'date_added': str(date_added),
            'due_date': item.get('dueDate', ''),
            'action': item.get('requiredAction', ''),
            'known_ransomware': item.get('knownRansomwareCampaignUse', ''),
            'source': 'CISA KEV',
        })
    epss = get_epss([v['cve'] for v in vulns])
    for v in vulns:
        v.update(epss.get(v['cve'], {}))
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
    except Exception:
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
        })
    epss = get_epss([v['cve'] for v in items])
    for v in items:
        v.update(epss.get(v['cve'], {}))
    return sorted(items, key=lambda x: (x.get('epss', 0), x.get('cvss') or 0), reverse=True)


def parse_feed(source, url):
    try:
        raw = fetch(url, timeout=20)
    except Exception:
        return []
    try:
        root = ET.fromstring(raw)
    except Exception:
        return []

    items = []
    channel_items = root.findall('.//item')
    if channel_items:
        for item in channel_items[:12]:
            title = strip_text(item.findtext('title'))
            link = strip_text(item.findtext('link'))
            pub = parse_date(item.findtext('pubDate'))
            desc = strip_text(item.findtext('description'))
            items.append({'source': source, 'title': title, 'url': link, 'date': str(pub or today()), 'summary': desc[:220]})
        return items

    ns = {'atom': 'http://www.w3.org/2005/Atom'}
    for item in root.findall('.//atom:entry', ns)[:12]:
        title = strip_text(item.findtext('atom:title', namespaces=ns))
        link_el = item.find('atom:link', ns)
        link = link_el.get('href') if link_el is not None else ''
        pub = parse_date(item.findtext('atom:updated', namespaces=ns) or item.findtext('atom:published', namespaces=ns))
        summary = strip_text(item.findtext('atom:summary', namespaces=ns) or item.findtext('atom:content', namespaces=ns))
        items.append({'source': source, 'title': title, 'url': link, 'date': str(pub or today()), 'summary': summary[:220]})
    return items


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
    return items[:10]


def md_table(headers, rows):
    out = ['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join(['---'] * len(headers)) + ' |']
    out.extend('| ' + ' | '.join(str(c).replace('\n', ' ') for c in row) + ' |' for row in rows)
    return '\n'.join(out)


def build_entries():
    date = str(today())
    kev = get_recent_kev()
    nvd = get_recent_nvd()
    research = get_research_watch()

    cve_rows = []
    for item in kev[:8]:
        cve_rows.append([
            item.get('cve'),
            f"{item.get('vendor')} {item.get('product')}".strip(),
            'KEV',
            f"{item.get('epss', 0):.3f}" if 'epss' in item else '-',
            item.get('date_added'),
        ])
    for item in nvd[:6]:
        if item.get('cve') not in {r[0] for r in cve_rows}:
            cve_rows.append([
                item.get('cve'),
                item.get('severity', 'UNKNOWN'),
                item.get('cvss', '-'),
                f"{item.get('epss', 0):.3f}" if 'epss' in item else '-',
                item.get('published'),
            ])
    cve_content = [
        '## 今日判断',
        '优先关注已经进入 CISA KEV、EPSS 较高、或过去 48 小时内由 NVD 收录的高危漏洞。KEV 表示已经有在野利用证据，应优先进入修复队列。',
        '',
        '## CVE 雷达',
        md_table(['CVE', '产品/严重性', '信号', 'EPSS', '日期'], cve_rows[:12]) if cve_rows else '今日未抓到高优先级 CVE 信号。',
        '',
        '## 防守建议',
        '- 先核对外网暴露资产、VPN、防火墙、身份系统和常用开源组件是否命中表内 CVE。',
        '- KEV 命中项按紧急变更处理；只有 CVSS 高但没有利用信号的项放入常规补丁队列。',
        '- 对命中产品补充日志检索：异常登录、Web exploit 痕迹、可疑进程创建、异常出站连接。',
        '',
        '## 来源',
        '- CISA Known Exploited Vulnerabilities Catalog',
        '- NVD CVE API 2.0',
        '- FIRST EPSS API',
    ]

    research_lines = ['## 专业团队研究观察']
    if research:
        for item in research[:8]:
            research_lines.append(f"- **{item['source']}** ({item['date']}): [{item['title']}]({item['url']})")
            if item.get('summary'):
                research_lines.append(f"  - {item['summary']}")
    else:
        research_lines.append('今日未抓到专业团队 RSS 新条目。')
    research_lines.extend([
        '',
        '## 为什么值得关注',
        '这些来源来自专业威胁研究团队，比普通新闻更接近攻击链、TTP、漏洞利用和检测建议。每日简报应优先阅读这类内容，再参考媒体报道。',
        '',
        '## 来源',
        '- Microsoft Threat Intelligence',
        '- Palo Alto Unit 42',
        '- Cisco Talos',
        '- The DFIR Report',
    ])

    action_lines = ['## 今日处置清单']
    if cve_rows:
        action_lines.extend([
            '1. 检查资产清单中是否存在 CVE 雷达表内产品。',
            '2. 对 CISA KEV 命中项建立单独跟踪，不要只按 CVSS 排序。',
            '3. 对近 14 天专业团队文章提到的攻击链，提取可落地检测点：进程、命令行、域名、文件路径、认证事件。',
            '4. 对暂无补丁但已有利用信号的产品，先做暴露面收缩、WAF/ACL、临时禁用高风险功能。',
        ])
    else:
        action_lines.append('1. 今日没有高优先级 CVE 信号，保持监控即可。')
    action_lines.extend([
        '',
        '## 输出边界',
        '此条由固定脚本生成，不依赖模型自由判断。模型只允许运行脚本并转发结果。',
    ])

    return [
        {
            'kind': 'cve_radar',
            'date': date,
            'title': f'CVE Radar - {date}',
            'content': '\n'.join(cve_content),
        },
        {
            'kind': 'threat_intel',
            'date': date,
            'title': f'专业团队威胁研究观察 - {date}',
            'content': '\n'.join(research_lines),
        },
        {
            'kind': 'defender_actions',
            'date': date,
            'title': f'防守行动清单 - {date}',
            'content': '\n'.join(action_lines),
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
