# Threat Intelligence Dashboard

An automated threat intelligence dashboard for a small homelab or security operations workflow.

The project collects daily signals from trusted vulnerability and security research sources, normalizes them into a constrained JSON format, and renders a focused web dashboard with:

- Resource Monitor
- Structured CVE Radar
- Detection Coverage
- Research Watch
- Defender Action Queue
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

scripts/
  generate_threat_intel.py   Fetches and formats daily intelligence
  export_daily_briefing.py   Exports an operator-readable Markdown briefing
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
THREAT_INTEL_SYSTEM_URL=http://remote-host:8765/api/system
THREAT_INTEL_DISCOVERIES_URL=http://remote-host:8765/api/discoveries
THREAT_INTEL_PIPELINE_URL=http://remote-host:8765/api/pipeline
THREAT_INTEL_PIPELINE_HISTORY_URL=http://remote-host:8765/api/pipeline-history
THREAT_INTEL_BRIEFING_URL=http://remote-host:8765/briefing.md
```

When running the dashboard locally but displaying a remote homelab node, set
`THREAT_INTEL_SYSTEM_URL`, `THREAT_INTEL_DISCOVERIES_URL`, and
`THREAT_INTEL_PIPELINE_URL` to the remote dashboard API endpoints. Set
`THREAT_INTEL_PIPELINE_HISTORY_URL` as well when you want local dashboard views
to mirror the remote run history. Set `THREAT_INTEL_BRIEFING_URL` when you want
the local Briefing tab to mirror the remote Markdown export.

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

## Automation

The pipeline is compatible with cron or an agent scheduler such as OpenClaw. The agent should only run the shell pipeline and should not edit dashboard data directly:

```bash
bash scripts/discoveries_pipeline.sh
```

## Safety Boundaries

- The dashboard API is read-only.
- The merge step accepts only the three allowed intelligence kinds.
- Structured CVE and research metadata is allowed only through fixed `items` and `sources` fields.
- Defender actions are generated as a constrained queue with priority, category, owner, due window, and related CVEs or sources.
- The Markdown briefing is generated only after validated data is merged.
- Detection guidance is rule-based and generated from CVE impact area, exploit signals, and local relevance.
- Local watchlist relevance is deterministic and read from `config/watchlist.json`.
- Collection diagnostics record source success/failure and item counts for KEV, NVD, EPSS, and each research feed.
- RSS research entries are filtered by security keywords to avoid conference, interview, or general technology content.
- Existing entries with the same date and title are updated instead of duplicated.
