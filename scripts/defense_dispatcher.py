#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(os.environ.get('THREAT_INTEL_ROOT', Path(__file__).resolve().parents[1]))
DASHBOARD_DIR = Path(os.environ.get('THREAT_INTEL_DASHBOARD_DIR', ROOT / 'dashboard'))
POLICY_FILE = Path(os.environ.get('THREAT_INTEL_DEFENSE_POLICY', ROOT / 'config' / 'defense_policy.json'))
HISTORY_FILE = Path(os.environ.get('THREAT_INTEL_DEFENSE_HISTORY', DASHBOARD_DIR / 'defense-history.json'))

SEVERITY = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def load_json(path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return default


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def read_input(path):
    if path == '-':
        return sys.stdin.read()
    return Path(path).read_text(encoding='utf-8')


def extract_telegram_text(update):
    if not isinstance(update, dict):
        return ''
    for key in ('message', 'channel_post', 'edited_message'):
        node = update.get(key)
        if isinstance(node, dict):
            return str(node.get('text') or node.get('caption') or '')
    return str(update.get('text') or '')


def parse_key_value_text(text):
    result = {}
    aliases = {
        'type': 'type',
        'alert': 'type',
        'source': 'source',
        'severity': 'severity',
        'host': 'host',
        'src_ip': 'src_ip',
        'source_ip': 'src_ip',
        'ip': 'src_ip',
        'count': 'count',
        'time': 'time',
    }
    for line in text.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
        elif '=' in line:
            key, value = line.split('=', 1)
        else:
            continue
        normalized = aliases.get(key.strip().lower())
        if normalized:
            result[normalized] = value.strip()
    return result


def normalize_alert(raw, telegram=False):
    if telegram:
        update = json.loads(raw)
        text = extract_telegram_text(update)
        match = re.search(r'\{.*\}', text, flags=re.S)
        if match:
            alert = json.loads(match.group(0))
        else:
            alert = parse_key_value_text(text)
            alert['raw_text'] = text
        alert['delivery'] = 'telegram'
    else:
        alert = json.loads(raw)

    if not isinstance(alert, dict):
        raise SystemExit('alert input must be a JSON object')

    normalized = {
        'source': str(alert.get('source') or 'telegram').strip(),
        'severity': str(alert.get('severity') or 'info').strip().lower(),
        'type': str(alert.get('type') or alert.get('kind') or 'unknown').strip().lower(),
        'host': str(alert.get('host') or 'unknown').strip(),
        'src_ip': str(alert.get('src_ip') or alert.get('source_ip') or alert.get('ip') or '').strip(),
        'count': int(alert.get('count') or 0),
        'time': str(alert.get('time') or alert.get('timestamp') or iso(now_utc())).strip(),
        'message': str(alert.get('message') or alert.get('raw_text') or '').strip()[:500],
        'delivery': alert.get('delivery') or ('telegram' if telegram else 'json'),
    }
    if normalized['type'] in {'ssh brute force', 'ssh-bruteforce', 'ssh_bruteforce_alert'}:
        normalized['type'] = 'ssh_bruteforce'
    return normalized


def policy_rule(policy, alert_type):
    for rule in policy.get('rules', []):
        if isinstance(rule, dict) and rule.get('type') == alert_type:
            return rule
    return None


def valid_public_ip(value, policy):
    try:
        ip = ipaddress.ip_address(value)
    except Exception:
        return False, 'invalid-ip'
    if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        return False, 'non-public-ip'
    for cidr in policy.get('protected_cidrs', []):
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return False, 'protected-cidr'
        except Exception:
            continue
    return True, str(ip)


def severity_allowed(alert_severity, minimum):
    return SEVERITY.get(alert_severity, 0) >= SEVERITY.get(str(minimum or 'critical').lower(), 4)


def command_for_block(ip, ttl_minutes, alert_id):
    comment = f'threat-intel {alert_id} ttl={ttl_minutes}m'
    return ['sudo', 'ufw', 'insert', '1', 'deny', 'from', ip, 'comment', comment]


def run_command(command, live):
    if not live:
        return {'mode': 'dry-run', 'command': command, 'returncode': 0, 'stdout': '', 'stderr': ''}
    proc = subprocess.run(command, text=True, capture_output=True, timeout=20, check=False)
    return {
        'mode': 'live',
        'command': command,
        'returncode': proc.returncode,
        'stdout': proc.stdout[-1000:],
        'stderr': proc.stderr[-1000:],
    }


def decision_for(alert, policy):
    rule = policy_rule(policy, alert['type'])
    if not rule:
        return {
            'status': 'requires_approval',
            'action': 'collect_evidence',
            'reason': 'No auto-defense rule exists for this alert type.',
            'ttl_minutes': None,
        }

    if alert.get('host') not in set(policy.get('trusted_hosts', [])):
        return {
            'status': 'rejected',
            'action': rule.get('action', 'none'),
            'reason': 'Alert host is not in trusted_hosts.',
            'ttl_minutes': None,
        }

    if not rule.get('auto_allowed'):
        return {
            'status': 'requires_approval',
            'action': rule.get('action', 'collect_evidence'),
            'reason': 'Policy requires human approval for this alert type.',
            'ttl_minutes': rule.get('ttl_minutes'),
        }

    if not severity_allowed(alert.get('severity'), rule.get('min_severity')):
        return {
            'status': 'recorded',
            'action': 'none',
            'reason': 'Severity is below the auto-defense threshold.',
            'ttl_minutes': None,
        }

    if int(alert.get('count') or 0) < int(rule.get('min_count') or 0):
        return {
            'status': 'recorded',
            'action': 'none',
            'reason': 'Event count is below the auto-defense threshold.',
            'ttl_minutes': None,
        }

    ok, ip_or_reason = valid_public_ip(alert.get('src_ip'), policy)
    if not ok:
        return {
            'status': 'rejected',
            'action': rule.get('action', 'none'),
            'reason': f'Source IP rejected: {ip_or_reason}.',
            'ttl_minutes': None,
        }

    return {
        'status': 'auto_allowed',
        'action': rule.get('action', 'block_ip_ttl'),
        'reason': rule.get('description', 'Policy allows automatic response.'),
        'ttl_minutes': int(rule.get('ttl_minutes') or 120),
        'normalized_ip': ip_or_reason,
    }


def telegram_reply(record):
    alert = record['alert']
    decision = record['decision']
    if record['status'] in {'executed', 'simulated'}:
        return (
            'Defense action completed\n\n'
            f"Alert: {alert['type']}\n"
            f"Host: {alert['host']}\n"
            f"Source IP: {alert.get('src_ip') or '-'}\n"
            f"Action: {decision['action']}\n"
            f"TTL: {decision.get('ttl_minutes') or '-'} minutes\n"
            f"Mode: {record['mode']}\n"
            f"Status: {record['status']}"
        )
    if record['status'] == 'requires_approval':
        return (
            'Approval required\n\n'
            f"Alert: {alert['type']}\n"
            f"Host: {alert['host']}\n"
            f"Suggested action: {decision['action']}\n"
            f"Reason: {decision['reason']}\n"
            f"Incident: {record['id']}"
        )
    return (
        'Defense action not executed\n\n'
        f"Alert: {alert['type']}\n"
        f"Host: {alert['host']}\n"
        f"Reason: {decision['reason']}\n"
        f"Status: {record['status']}"
    )


def append_history(record, policy):
    history = load_json(HISTORY_FILE, [])
    if not isinstance(history, list):
        history = []
    history.insert(0, record)
    history = history[: int(policy.get('history_limit') or 100)]
    write_json(HISTORY_FILE, history)


def handle_alert(alert, policy):
    received = now_utc()
    raw_id = f"{alert.get('time')}|{alert.get('type')}|{alert.get('host')}|{alert.get('src_ip')}|{received.timestamp()}"
    alert_id = 'def-' + hashlib.sha256(raw_id.encode()).hexdigest()[:12]
    decision = decision_for(alert, policy)
    live = os.environ.get('DEFENSE_EXECUTION_MODE') == 'live' and os.environ.get('DEFENSE_ALLOW_LIVE') == '1'
    mode = 'live' if live else 'dry-run'
    expires_at = None
    execution = None
    status = decision['status']

    if decision['status'] == 'auto_allowed' and decision.get('action') == 'block_ip_ttl':
        ttl = int(decision.get('ttl_minutes') or 120)
        expires_at = iso(received + timedelta(minutes=ttl))
        command = command_for_block(decision['normalized_ip'], ttl, alert_id)
        execution = run_command(command, live)
        status = 'executed' if live and execution['returncode'] == 0 else 'simulated'
        if live and execution['returncode'] != 0:
            status = 'failed'
            decision['reason'] = 'Live command failed.'

    record = {
        'id': alert_id,
        'received_at': iso(received),
        'status': status,
        'mode': mode,
        'alert': alert,
        'decision': decision,
        'execution': execution,
        'expires_at': expires_at,
    }
    record['telegram_reply'] = telegram_reply(record)
    append_history(record, policy)
    return record


def main():
    parser = argparse.ArgumentParser(description='Policy-gated defensive automation dispatcher')
    parser.add_argument('input', help='alert JSON file path, Telegram update JSON file path, or - for stdin')
    parser.add_argument('--telegram-update', action='store_true', help='parse input as a Telegram update object')
    args = parser.parse_args()

    policy = load_json(POLICY_FILE, {})
    raw = read_input(args.input)
    alert = normalize_alert(raw, telegram=args.telegram_update)
    record = handle_alert(alert, policy)
    print(json.dumps(record, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
