#!/usr/bin/env python3
import json
import os
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import defense_dispatcher


HOST = os.environ.get('DEFENSE_WEBHOOK_HOST', '127.0.0.1')
PORT = int(os.environ.get('DEFENSE_WEBHOOK_PORT', '8787'))
TOKEN = os.environ.get('DEFENSE_WEBHOOK_TOKEN', '')
MAX_BYTES = int(os.environ.get('DEFENSE_WEBHOOK_MAX_BYTES', '65536'))
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
TELEGRAM_ALLOWED_CHAT_ID = os.environ.get('TELEGRAM_ALLOWED_CHAT_ID', TELEGRAM_CHAT_ID)


def send_json(handler, status, payload):
    raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def read_body(handler):
    content_length = int(handler.headers.get('Content-Length') or '0')
    if content_length <= 0:
        raise ValueError('request body is required')
    if content_length > MAX_BYTES:
        raise ValueError('request body is too large')
    return handler.rfile.read(content_length).decode('utf-8')


def authorized(handler):
    if not TOKEN:
        return True
    parsed = urllib.parse.urlparse(handler.path)
    query = urllib.parse.parse_qs(parsed.query)
    supplied = (
        handler.headers.get('X-Defense-Token')
        or handler.headers.get('X-Telegram-Bot-Api-Secret-Token')
        or (query.get('token') or [''])[0]
    )
    return supplied == TOKEN


def telegram_chat_id(update):
    if not isinstance(update, dict):
        return ''
    for key in ('message', 'channel_post', 'edited_message'):
        node = update.get(key)
        if isinstance(node, dict):
            chat = node.get('chat')
            if isinstance(chat, dict) and chat.get('id') is not None:
                return str(chat.get('id'))
    return ''


def send_telegram_message(chat_id, text):
    if not TELEGRAM_BOT_TOKEN:
        return {'sent': False, 'reason': 'TELEGRAM_BOT_TOKEN is not configured'}
    target_chat = str(TELEGRAM_CHAT_ID or chat_id or '')
    if not target_chat:
        return {'sent': False, 'reason': 'telegram chat id is unavailable'}
    if TELEGRAM_ALLOWED_CHAT_ID and target_chat != str(TELEGRAM_ALLOWED_CHAT_ID):
        return {'sent': False, 'reason': 'telegram chat id is not allowed'}

    url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
    payload = urllib.parse.urlencode({
        'chat_id': target_chat,
        'text': text[:3900],
        'disable_web_page_preview': 'true',
    }).encode('utf-8')
    request = urllib.request.Request(url, data=payload, method='POST')
    request.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            raw = response.read().decode('utf-8')
        return {'sent': True, 'status': response.status, 'response': raw[:500]}
    except Exception as error:
        return {'sent': False, 'reason': str(error)[:500]}


def dispatch(raw, telegram=False):
    policy = defense_dispatcher.load_json(defense_dispatcher.POLICY_FILE, {})
    alert = defense_dispatcher.normalize_alert(raw, telegram=telegram)
    return defense_dispatcher.handle_alert(alert, policy)


class DefenseWebhookHandler(BaseHTTPRequestHandler):
    server_version = 'DefenseWebhook/1.0'

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/healthz':
            send_json(self, 200, {
                'ok': True,
                'service': 'defense-webhook',
                'telegram_reply_enabled': bool(TELEGRAM_BOT_TOKEN),
                'auth_required': bool(TOKEN),
            })
            return
        send_json(self, 404, {'ok': False, 'error': 'not found'})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in {'/alert', '/telegram'}:
            send_json(self, 404, {'ok': False, 'error': 'not found'})
            return
        if not authorized(self):
            send_json(self, 401, {'ok': False, 'error': 'unauthorized'})
            return

        try:
            raw = read_body(self)
            is_telegram = parsed.path == '/telegram'
            record = dispatch(raw, telegram=is_telegram)
            telegram_result = {'sent': False, 'reason': 'not a telegram endpoint'}
            if is_telegram:
                update = json.loads(raw)
                telegram_result = send_telegram_message(telegram_chat_id(update), record.get('telegram_reply', ''))
            send_json(self, 200, {'ok': True, 'record': record, 'telegram': telegram_result})
        except Exception as error:
            send_json(self, 400, {'ok': False, 'error': str(error)})

    def log_message(self, fmt, *args):
        sys.stderr.write('%s - %s\n' % (self.address_string(), fmt % args))


def main():
    server = ThreadingHTTPServer((HOST, PORT), DefenseWebhookHandler)
    print(f'Defense webhook listening on http://{HOST}:{PORT}/')
    print('Endpoints: POST /alert, POST /telegram, GET /healthz')
    server.serve_forever()


if __name__ == '__main__':
    main()
