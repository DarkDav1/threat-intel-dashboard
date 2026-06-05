const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const os = require('os');

const PORT = Number(process.env.COCKY_DASHBOARD_PORT || 8765);
const HOST = process.env.COCKY_DASHBOARD_HOST || '0.0.0.0';
const PUBLIC_DIR = path.join(__dirname, 'public');
const DASHBOARD_ROOT = process.env.THREAT_INTEL_DASHBOARD_DIR || __dirname;
const DISCOVERIES_FILE = path.join(DASHBOARD_ROOT, 'discoveries.json');

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
};

function sendJson(res, status, payload) {
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
    });
    res.end(JSON.stringify(payload));
}

async function readDiscoveries() {
    try {
        const raw = await fs.readFile(DISCOVERIES_FILE, 'utf-8');
        const data = JSON.parse(raw);
        return {
            cve_radar: data.cve_radar || { entries: [] },
            threat_intel: data.threat_intel || { entries: [] },
            defender_actions: data.defender_actions || { entries: [] },
        };
    } catch (error) {
        return {
            cve_radar: { entries: [] },
            threat_intel: { entries: [] },
            defender_actions: { entries: [] },
        };
    }
}

async function getHealth() {
    const data = await readDiscoveries();
    return {
        ok: true,
        hostname: os.hostname(),
        uptimeSeconds: Math.round(os.uptime()),
        sections: Object.fromEntries(
            Object.entries(data).map(([kind, value]) => [kind, Array.isArray(value.entries) ? value.entries.length : 0])
        ),
    };
}

function normalizeUrl(url) {
    if (!url || url === '/dashboard' || url === '/dashboard/') return '/';
    if (url.startsWith('/dashboard/api/')) return url.slice('/dashboard'.length);
    if (url.startsWith('/dashboard/')) return url.slice('/dashboard'.length);
    return url;
}

const server = http.createServer(async (req, res) => {
    const normalizedUrl = normalizeUrl(req.url || '/');

    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET,OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        });
        res.end();
        return;
    }

    try {
        if (normalizedUrl === '/api/discoveries') {
            sendJson(res, 200, await readDiscoveries());
            return;
        }

        if (normalizedUrl === '/api/health' || normalizedUrl === '/api/system') {
            sendJson(res, 200, await getHealth());
            return;
        }

        if (normalizedUrl.startsWith('/api/')) {
            sendJson(res, 404, { error: 'API endpoint not found' });
            return;
        }

        const safePath = path.normalize(normalizedUrl).replace(/^(\.\.[/\\])+/, '');
        const filePath = path.join(PUBLIC_DIR, safePath === '/' ? 'index.html' : safePath);
        if (!filePath.startsWith(PUBLIC_DIR)) {
            res.writeHead(403);
            res.end('Forbidden');
            return;
        }

        const content = await fs.readFile(filePath);
        const ext = path.extname(filePath).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
        res.end(content);
    } catch (error) {
        if (error.code === 'ENOENT') {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Not found');
            return;
        }
        sendJson(res, 500, { error: 'Internal server error' });
    }
});

server.listen(PORT, HOST, () => {
    console.log(`Threat Intelligence Dashboard listening on http://${HOST}:${PORT}/`);
});
