# Threat Intelligence Dashboard

An automated threat intelligence dashboard for a small homelab or security operations workflow.

The project collects daily signals from trusted vulnerability and security research sources, normalizes them into a constrained JSON format, and renders a focused web dashboard with:

- Resource Monitor
- Structured CVE Radar
- Detection Coverage
- Research Watch
- Defender Action Queue
- Telegram-ready Defense Ops history
- Export-ready Daily Briefing
- Pipeline Health
- Pipeline Run History
- Source Coverage diagnostics
- Watchlist-based local relevance scoring

## Data Sources

- CISA Known Exploited Vulnerabilities
- NVD CVE API 2.0
- FIRST EPSS
- Microsoft Threat Intelligence
- Palo Alto Unit 42
- Cisco Talos
- The DFIR Report
- Mandiant
- CrowdStrike
- Elastic Security
- Rapid7
- Huntress

## Why This Exists

The dashboard is designed to avoid loosely generated "security news" summaries. The collection pipeline is deterministic, source constrained, and only accepts three allowed content types:

- `cve_radar`
- `threat_intel`
- `defender_actions`

This keeps the UI focused on operationally useful threat intelligence instead of general technology news.

## Project Structure

```text
dashboard/
  public/index.html          Web dashboard
  server.js                  Small Node.js static/API server with read-only telemetry, briefing, and pipeline health

config/
  watchlist.json             Local relevance profile for assets, technologies, and security interests
  defense_policy.json        Policy gate for defensive automation

scripts/
  generate_threat_intel.py   Fetches and formats daily intelligence
  export_daily_briefing.py   Exports an operator-readable Markdown briefing
  defense_dispatcher.py      Validates alerts and runs policy-gated defensive runbooks
  defense_webhook_server.py  Receives alert or Telegram webhook events and calls the dispatcher
  discoveries_pipeline.sh    Runs generation, append, and merge
  append_discoveries_json_to_inbox.py
  merge_discoveries_inbox.py
  capture_daily_surfing_output.py
```

## Quick Start

Generate and merge the latest intelligence:

```bash
bash scripts/discoveries_pipeline.sh
```

The pipeline also exports:

```text
dashboard/daily-briefing.md
```

Start the dashboard:

```bash
node dashboard/server.js
```

Open:

```text
http://localhost:8765
```

The landing page is a read-only resource monitor for the host running the pipeline. It includes threshold-based health status, the last telemetry update time, telemetry source status, and short in-browser trend charts for CPU, memory, temperature, and network throughput. Threat intelligence views are available in the navigation.

The CVE Radar view supports triage filtering by search text, priority, CISA KEV status, and local watchlist relevance. It shows risk score, relevance score, impact area, and matched watchlist groups.

The Detection view maps prioritized CVEs to deterministic log-source guidance,
hunt ideas, and MITRE ATT&CK technique references. This is intended to help an
analyst move from patch triage to detection coverage review.

## Configuration

The default layout works from the repository root. These environment variables can override paths and network settings:

```bash
COCKY_DASHBOARD_HOST=0.0.0.0
COCKY_DASHBOARD_PORT=8765
THREAT_INTEL_ROOT=/path/to/repo
THREAT_INTEL_DASHBOARD_DIR=/path/to/repo/dashboard
THREAT_INTEL_OUTPUT=/path/to/discoveries-generated.json
THREAT_INTEL_WATCHLIST=/path/to/watchlist.json
THREAT_INTEL_BRIEFING=/path/to/daily-briefing.md
THREAT_INTEL_DISCOVERIES=/path/to/discoveries.json
THREAT_INTEL_INBOX=/path/to/discoveries-inbox.json
THREAT_INTEL_PIPELINE_HEALTH=/path/to/pipeline-health.json
THREAT_INTEL_PIPELINE_HISTORY=/path/to/pipeline-history.json
THREAT_INTEL_DEFENSE_POLICY=/path/to/defense_policy.json
THREAT_INTEL_DEFENSE_HISTORY=/path/to/defense-history.json
DEFENSE_WEBHOOK_HOST=127.0.0.1
DEFENSE_WEBHOOK_PORT=8787
DEFENSE_WEBHOOK_TOKEN=shared-secret
TELEGRAM_BOT_TOKEN=123456:telegram-token
TELEGRAM_CHAT_ID=1862711362
TELEGRAM_ALLOWED_CHAT_ID=1862711362
THREAT_INTEL_SYSTEM_URL=http://remote-host:8765/api/system
THREAT_INTEL_DISCOVERIES_URL=http://remote-host:8765/api/discoveries
THREAT_INTEL_PIPELINE_URL=http://remote-host:8765/api/pipeline
THREAT_INTEL_PIPELINE_HISTORY_URL=http://remote-host:8765/api/pipeline-history
THREAT_INTEL_BRIEFING_URL=http://remote-host:8765/briefing.md
THREAT_INTEL_DEFENSE_HISTORY_URL=http://remote-host:8765/api/defense-history
```

When running the dashboard locally but displaying a remote homelab node, set
`THREAT_INTEL_SYSTEM_URL`, `THREAT_INTEL_DISCOVERIES_URL`, and
`THREAT_INTEL_PIPELINE_URL` to the remote dashboard API endpoints. Set
`THREAT_INTEL_PIPELINE_HISTORY_URL` as well when you want local dashboard views
to mirror the remote run history. Set `THREAT_INTEL_BRIEFING_URL` when you want
the local Briefing tab to mirror the remote Markdown export. Set
`THREAT_INTEL_DEFENSE_HISTORY_URL` when you want the local Defense Ops tab to
mirror remote defense history.

## Local Relevance Watchlist

`config/watchlist.json` defines technologies and security areas that matter to
the environment. The generator uses this file to raise priority for matching
CVEs and research posts without changing the trusted source boundaries.

Each watchlist group has:

- `name`
- `weight`
- `keywords`

Generated CVE items include:

- `base_risk_score`
- `risk_score`
- `relevance_score`
- `watchlist_matches`
- `impact_area`
- `risk_factors`
- `detection`

The dashboard can filter CVEs to watchlist matches only.

## Daily Briefing

After merge completes, `scripts/export_daily_briefing.py` creates a Markdown
briefing from validated dashboard data. It includes:

- Executive summary
- Top vulnerabilities
- Local relevance summary
- Detection guidance
- Defender actions
- Research watch
- Source coverage

The dashboard serves it through `/api/briefing` for preview and `/briefing.md`
for direct Markdown access.

## Defense Ops MVP

`scripts/defense_dispatcher.py` accepts either normalized alert JSON or a
Telegram update containing JSON or key-value alert text. The dispatcher validates
the alert against `config/defense_policy.json`, writes a defense history entry,
and returns a Telegram-ready reply.

Default behavior is dry-run. The first auto-allowed rule is intentionally narrow:

- Alert type: `ssh_bruteforce`
- Action: temporary single-IP UFW block
- TTL: 120 minutes
- Guardrails: trusted host only, minimum severity/count, public IP only, protected CIDRs blocked from action

Example normalized alert:

```json
{
  "source": "wazuh",
  "severity": "high",
  "type": "ssh_bruteforce",
  "host": "gpd",
  "src_ip": "1.2.3.4",
  "count": 50,
  "time": "2026-06-06T10:30:00Z"
}
```

Run in dry-run mode:

```bash
python3 scripts/defense_dispatcher.py alert.json
```

Live mode requires both environment variables:

```bash
DEFENSE_EXECUTION_MODE=live DEFENSE_ALLOW_LIVE=1 python3 scripts/defense_dispatcher.py alert.json
```

The dashboard exposes the resulting history through `/api/defense-history` and
the Defense Ops tab. The dashboard does not execute defense actions directly.

## Telegram Automation Receiver

`scripts/defense_webhook_server.py` is the first automation entry point for
real-time alert handling. It accepts two POST endpoints:

- `/alert` for normalized alert JSON
- `/telegram` for Telegram webhook update JSON

Both endpoints call `defense_dispatcher.py` internally, so the same policy gate,
dry-run default, protected CIDRs, trusted hosts, and history writing are used.
The webhook service does not expose any dashboard write or command endpoint.

Start the receiver locally:

```bash
DEFENSE_WEBHOOK_TOKEN=change-me \
python3 scripts/defense_webhook_server.py
```

Health check:

```bash
curl http://127.0.0.1:8787/healthz
```

Send a normalized alert:

```bash
curl -sS http://127.0.0.1:8787/alert \
  -H 'Content-Type: application/json' \
  -H 'X-Defense-Token: change-me' \
  -d '{
    "source": "wazuh",
    "severity": "high",
    "type": "ssh_bruteforce",
    "host": "gpd",
    "src_ip": "1.2.3.4",
    "count": 20,
    "message": "Repeated failed SSH logins"
  }'
```

Telegram replies are optional. If `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`
are configured, the receiver sends the dispatcher result back to Telegram.
If they are not configured, events are still recorded and returned in the HTTP
response.

Register a Telegram webhook through your reverse proxy URL:

```bash
curl "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook" \
  -d "url=https://example.com/telegram" \
  -d "secret_token=${DEFENSE_WEBHOOK_TOKEN}"
```

When using Telegram's `secret_token`, configure the reverse proxy to copy it to
the request header. The receiver accepts Telegram's native
`X-Telegram-Bot-Api-Secret-Token` header as well as `X-Defense-Token`. Keep the
Python receiver bound to `127.0.0.1` unless it is behind a reverse proxy.

## Automation

The pipeline is compatible with cron or an agent scheduler such as OpenClaw. The agent should only run the shell pipeline and should not edit dashboard data directly:

```bash
bash scripts/discoveries_pipeline.sh
```

## Codex Ops Watch Automation

The live Codex App automation is named:

```text
Threat Intel Ops Watch
```

Automation id:

```text
threat-intel-ops-watch
```

It runs hourly as a read-only operations watch. The automation reads only these
local dashboard APIs:

- `http://127.0.0.1:9876/api/defense-history`
- `http://127.0.0.1:9876/api/pipeline`
- `http://127.0.0.1:9876/api/briefing`

It reports in concise Chinese when attention is needed:

- `requires_approval`, `failed`, or `rejected` defense events
- stale or failed pipeline status
- missing or unusually old briefing data

The automation is intentionally not part of the real-time defense path. Real-time
alerts go to the gpd webhook receiver, which calls the deterministic dispatcher.
Codex only performs scheduled review and summarization.

Current Codex automation prompt:

```text
Check the threat intelligence dashboard operational state by reading only these local APIs: http://127.0.0.1:9876/api/defense-history, http://127.0.0.1:9876/api/pipeline, and http://127.0.0.1:9876/api/briefing. Summarize in concise Chinese only when attention is needed: requires_approval, failed, rejected defense events, stale or failed pipeline status, missing briefing, or unusually old briefing data. If everything is healthy, report a short healthy status. Do not execute any commands that block IPs, restart services, delete files, modify firewall rules, modify system configuration, or change repository files.
```

## Safety Boundaries

- The dashboard API is read-only.
- Defense automation is policy-gated and dry-run by default.
- The first auto-defense runbook only permits a temporary single public IP block for SSH brute force.
- Codex automation is read-only and limited to operations review, not real-time defense execution.
- The merge step accepts only the three allowed intelligence kinds.
- Structured CVE and research metadata is allowed only through fixed `items` and `sources` fields.
- Defender actions are generated as a constrained queue with priority, category, owner, due window, and related CVEs or sources.
- The Markdown briefing is generated only after validated data is merged.
- Detection guidance is rule-based and generated from CVE impact area, exploit signals, and local relevance.
- Local watchlist relevance is deterministic and read from `config/watchlist.json`.
- Collection diagnostics record source success/failure and item counts for KEV, NVD, EPSS, and each research feed.
- RSS research entries are filtered by security keywords to avoid conference, interview, or general technology content.
- Existing entries with the same date and title are updated instead of duplicated.
