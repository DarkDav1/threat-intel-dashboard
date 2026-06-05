const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const { exec } = require('child_process');
const util = require('util');

const execAsync = util.promisify(exec);

const PORT = Number(process.env.COCKY_DASHBOARD_PORT || 8765);
const HOST = process.env.COCKY_DASHBOARD_HOST || '0.0.0.0';
const PUBLIC_DIR = path.join(__dirname, 'public');
const DASHBOARD_ROOT = process.env.THREAT_INTEL_DASHBOARD_DIR || __dirname;
const DISCOVERIES_FILE = path.join(DASHBOARD_ROOT, 'discoveries.json');
const PIPELINE_HEALTH_FILE = path.join(DASHBOARD_ROOT, 'pipeline-health.json');
const PIPELINE_HISTORY_FILE = path.join(DASHBOARD_ROOT, 'pipeline-history.json');
const BRIEFING_FILE = path.join(DASHBOARD_ROOT, 'daily-briefing.md');
const DEFENSE_HISTORY_FILE = path.join(DASHBOARD_ROOT, 'defense-history.json');
const REMOTE_SYSTEM_URL = process.env.THREAT_INTEL_SYSTEM_URL || '';
const REMOTE_DISCOVERIES_URL = process.env.THREAT_INTEL_DISCOVERIES_URL || '';
const REMOTE_PIPELINE_URL = process.env.THREAT_INTEL_PIPELINE_URL || '';
const REMOTE_PIPELINE_HISTORY_URL = process.env.THREAT_INTEL_PIPELINE_HISTORY_URL || '';
const REMOTE_BRIEFING_URL = process.env.THREAT_INTEL_BRIEFING_URL || '';
const REMOTE_DEFENSE_HISTORY_URL = process.env.THREAT_INTEL_DEFENSE_HISTORY_URL || '';

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.md': 'text/markdown; charset=utf-8',
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

function sendText(res, status, text, contentType = 'text/plain; charset=utf-8') {
    res.writeHead(status, {
        'Content-Type': contentType,
        'Access-Control-Allow-Origin': '*',
    });
    res.end(text);
}

function fetchJson(url, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const transport = parsed.protocol === 'https:' ? require('https') : require('http');
        const request = transport.request(parsed, { method: 'GET', timeout: timeoutMs }, response => {
            let raw = '';
            response.setEncoding('utf8');
            response.on('data', chunk => { raw += chunk; });
            response.on('end', () => {
                if (response.statusCode < 200 || response.statusCode >= 300) {
                    reject(new Error(`Remote API returned ${response.statusCode}`));
                    return;
                }
                try {
                    resolve(JSON.parse(raw));
                } catch (error) {
                    reject(new Error('Remote API returned invalid JSON'));
                }
            });
        });
        request.on('timeout', () => request.destroy(new Error('Remote API timeout')));
        request.on('error', reject);
        request.end();
    });
}

function fetchText(url, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const transport = parsed.protocol === 'https:' ? require('https') : require('http');
        const request = transport.request(parsed, { method: 'GET', timeout: timeoutMs }, response => {
            let raw = '';
            response.setEncoding('utf8');
            response.on('data', chunk => { raw += chunk; });
            response.on('end', () => {
                if (response.statusCode < 200 || response.statusCode >= 300) {
                    reject(new Error(`Remote API returned ${response.statusCode}`));
                    return;
                }
                resolve(raw);
            });
        });
        request.on('timeout', () => request.destroy(new Error('Remote API timeout')));
        request.on('error', reject);
        request.end();
    });
}

function normalizeDiscoveries(data) {
    return {
        cve_radar: data.cve_radar || { entries: [] },
        threat_intel: data.threat_intel || { entries: [] },
        defender_actions: data.defender_actions || { entries: [] },
    };
}

function pipelineFreshness(pipeline) {
    const finished = pipeline && pipeline.finished_at ? new Date(pipeline.finished_at) : null;
    if (!finished || Number.isNaN(finished.getTime())) {
        return {
            status: 'unknown',
            age_minutes: null,
            age_label: 'No completed run recorded',
            message: 'No completed pipeline run has been recorded yet.',
        };
    }
    const ageMinutes = Math.max(0, Math.round((Date.now() - finished.getTime()) / 60000));
    const ageHours = ageMinutes / 60;
    let status = 'fresh';
    let message = 'Pipeline output is fresh.';
    if (ageHours >= 24) {
        status = 'stale';
        message = 'Pipeline output is older than 24 hours.';
    } else if (ageHours >= 8) {
        status = 'warning';
        message = 'Pipeline output is older than 8 hours.';
    }
    const ageLabel = ageMinutes < 60
        ? `${ageMinutes}m old`
        : `${Math.floor(ageMinutes / 60)}h ${ageMinutes % 60}m old`;
    return { status, age_minutes: ageMinutes, age_label: ageLabel, message };
}

function enrichPipelineHealth(pipeline) {
    const normalized = pipeline && typeof pipeline === 'object' ? pipeline : {};
    return { ...normalized, freshness: pipelineFreshness(normalized) };
}

async function readBriefing() {
    try {
        if (REMOTE_BRIEFING_URL) {
            return await fetchText(REMOTE_BRIEFING_URL);
        }
        return await fs.readFile(BRIEFING_FILE, 'utf-8');
    } catch (error) {
        return '# Threat Intelligence Briefing\n\nNo briefing has been generated yet.\n';
    }
}

function briefingMeta(markdown) {
    const title = (markdown.match(/^#\s+(.+)$/m) || [])[1] || 'Threat Intelligence Briefing';
    const generated = (markdown.match(/Generated at:\s+`([^`]+)`/) || [])[1] || null;
    return {
        title,
        generated_at: generated,
        bytes: Buffer.byteLength(markdown, 'utf8'),
    };
}

async function readDiscoveries() {
    try {
        if (REMOTE_DISCOVERIES_URL) {
            return normalizeDiscoveries(await fetchJson(REMOTE_DISCOVERIES_URL));
        }
        const raw = await fs.readFile(DISCOVERIES_FILE, 'utf-8');
        return normalizeDiscoveries(JSON.parse(raw));
    } catch (error) {
        return {
            cve_radar: { entries: [] },
            threat_intel: { entries: [] },
            defender_actions: { entries: [] },
        };
    }
}

async function readPipelineHealth() {
    try {
        if (REMOTE_PIPELINE_URL) {
            return enrichPipelineHealth(await fetchJson(REMOTE_PIPELINE_URL));
        }
        const raw = await fs.readFile(PIPELINE_HEALTH_FILE, 'utf-8');
        return enrichPipelineHealth(JSON.parse(raw));
    } catch (error) {
        return enrichPipelineHealth({
            status: 'unknown',
            stage: 'unknown',
            exit_code: null,
            message: 'No pipeline run has been recorded yet.',
            started_at: null,
            finished_at: null,
            generated_items: null,
            append: null,
            merge: null,
        });
    }
}

async function readPipelineHistory() {
    try {
        if (REMOTE_PIPELINE_HISTORY_URL) {
            const remote = await fetchJson(REMOTE_PIPELINE_HISTORY_URL);
            return Array.isArray(remote) ? remote.slice(0, 20) : [];
        }
        const raw = await fs.readFile(PIPELINE_HISTORY_FILE, 'utf-8');
        const data = JSON.parse(raw);
        return Array.isArray(data) ? data.slice(0, 20) : [];
    } catch (error) {
        return [];
    }
}

async function readDefenseHistory() {
    try {
        if (REMOTE_DEFENSE_HISTORY_URL) {
            const remote = await fetchJson(REMOTE_DEFENSE_HISTORY_URL);
            return Array.isArray(remote) ? remote.slice(0, 100) : [];
        }
        const raw = await fs.readFile(DEFENSE_HISTORY_FILE, 'utf-8');
        const data = JSON.parse(raw);
        return Array.isArray(data) ? data.slice(0, 100) : [];
    } catch (error) {
        return [];
    }
}

async function getDiskUsage() {
    const disk = { total: 0, used: 0, free: 0, percent: 0 };
    try {
        const { stdout } = await execAsync('df -k / | tail -n 1', { timeout: 5000 });
        const parts = stdout.trim().split(/\s+/);
        if (parts.length >= 6) {
            disk.total = Number(parts[1]) * 1024;
            disk.used = Number(parts[2]) * 1024;
            disk.free = Number(parts[3]) * 1024;
            disk.percent = Number(parts[4].replace('%', ''));
        }
    } catch (error) {}
    return disk;
}

async function getBattery() {
    const battery = { percent: null, charging: false, status: 'Unavailable', watts: null };
    try {
        const capacity = await fs.readFile('/sys/class/power_supply/BAT0/capacity', 'utf-8');
        const status = await fs.readFile('/sys/class/power_supply/BAT0/status', 'utf-8');
        battery.percent = Number(capacity.trim());
        battery.status = status.trim();
        battery.charging = battery.status === 'Charging';
        try {
            const powerMicro = await fs.readFile('/sys/class/power_supply/BAT0/power_now', 'utf-8');
            battery.watts = Number(powerMicro.trim()) / 1000000;
        } catch (error) {}
    } catch (error) {}
    return battery;
}

async function getTemperature() {
    const temperature = { cpu: null, ssd: null };
    try {
        const { stdout } = await execAsync('sensors 2>/dev/null', { timeout: 5000 });
        const tctlMatch = stdout.match(/Tctl:\s*\+([\d.]+)°C/);
        const nvmeMatch = stdout.match(/Composite:\s*\+([\d.]+)°C/);
        if (tctlMatch) temperature.cpu = Number(tctlMatch[1]);
        if (nvmeMatch) temperature.ssd = Number(nvmeMatch[1]);
    } catch (error) {}
    if (temperature.cpu === null) {
        try {
            const raw = await fs.readFile('/sys/class/thermal/thermal_zone1/temp', 'utf-8');
            temperature.cpu = Number(raw.trim()) / 1000;
        } catch (error) {}
    }
    return temperature;
}

async function getNetworkCounters() {
    const counters = { rx: 0, tx: 0 };
    try {
        const netDev = await fs.readFile('/proc/net/dev', 'utf-8');
        for (const line of netDev.split('\n')) {
            if (!line.includes(':') || line.includes('lo:')) continue;
            const parts = line.trim().split(/\s+/);
            counters.rx += Number(parts[1]) || 0;
            counters.tx += Number(parts[9]) || 0;
        }
    } catch (error) {}
    return counters;
}

async function getTopProcesses() {
    try {
        const { stdout } = await execAsync('ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 7', { timeout: 5000 });
        return stdout.trim().split('\n').slice(1).map(line => {
            const match = line.trim().match(/^(\d+)\s+(.+?)\s+([0-9.]+)\s+([0-9.]+)$/);
            if (!match) return null;
            return {
                pid: match[1],
                name: match[2],
                cpu: Number(match[3]),
                mem: Number(match[4]),
            };
        }).filter(Boolean);
    } catch (error) {
        return [];
    }
}

async function getSystemInfo() {
    if (REMOTE_SYSTEM_URL) {
        const remote = await fetchJson(REMOTE_SYSTEM_URL);
        return { ...remote, proxied: true, resourceSource: REMOTE_SYSTEM_URL };
    }

    const cpus = os.cpus();
    const load = os.loadavg()[0] || 0;
    const memTotal = os.totalmem();
    const memFree = os.freemem();
    const memUsed = memTotal - memFree;

    const [disk, battery, temperature, netStat, topProcesses, discoveries] = await Promise.all([
        getDiskUsage(),
        getBattery(),
        getTemperature(),
        getNetworkCounters(),
        getTopProcesses(),
        readDiscoveries(),
    ]);

    return {
        ok: true,
        hostname: os.hostname(),
        platform: os.platform(),
        uptime: os.uptime(),
        cpu: {
            model: cpus[0] ? cpus[0].model : 'Unknown CPU',
            cores: cpus.length,
            load: load.toFixed(2),
            usage: Math.min(100, (load / Math.max(cpus.length, 1)) * 100).toFixed(1),
        },
        memory: {
            total: memTotal,
            free: memFree,
            used: memUsed,
            percent: ((memUsed / memTotal) * 100).toFixed(1),
        },
        disk,
        battery,
        temperature,
        netStat,
        topProcesses,
        sections: Object.fromEntries(
            Object.entries(discoveries).map(([kind, value]) => [kind, Array.isArray(value.entries) ? value.entries.length : 0])
        ),
    };
}

async function getHealth() {
    const discoveries = await readDiscoveries();
    const pipeline = await readPipelineHealth();
    return {
        ok: true,
        hostname: os.hostname(),
        uptimeSeconds: Math.round(os.uptime()),
        sections: Object.fromEntries(
            Object.entries(discoveries).map(([kind, value]) => [kind, Array.isArray(value.entries) ? value.entries.length : 0])
        ),
        pipeline: {
            status: pipeline.status,
            stage: pipeline.stage,
            finished_at: pipeline.finished_at,
            freshness: pipeline.freshness,
        },
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

        if (normalizedUrl === '/api/briefing') {
            const markdown = await readBriefing();
            sendJson(res, 200, { ...briefingMeta(markdown), markdown });
            return;
        }

        if (normalizedUrl === '/briefing.md') {
            sendText(res, 200, await readBriefing(), 'text/markdown; charset=utf-8');
            return;
        }

        if (normalizedUrl === '/api/system') {
            sendJson(res, 200, await getSystemInfo());
            return;
        }

        if (normalizedUrl === '/api/pipeline') {
            sendJson(res, 200, await readPipelineHealth());
            return;
        }

        if (normalizedUrl === '/api/pipeline-history') {
            sendJson(res, 200, await readPipelineHistory());
            return;
        }

        if (normalizedUrl === '/api/defense-history') {
            sendJson(res, 200, await readDefenseHistory());
            return;
        }

        if (normalizedUrl === '/api/health') {
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
