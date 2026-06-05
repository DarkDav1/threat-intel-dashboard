# Threat Intelligence Dashboard

An automated threat intelligence dashboard for a small homelab or security operations workflow.

The project collects daily signals from trusted vulnerability and security research sources, normalizes them into a constrained JSON format, and renders a focused web dashboard with:

- Resource Monitor
- Structured CVE Radar
- Research Watch
- Defender Action Queue
- Pipeline Health

## Data Sources

- CISA Known Exploited Vulnerabilities
- NVD CVE API 2.0
- FIRST EPSS
- Microsoft Threat Intelligence
- Palo Alto Unit 42
- Cisco Talos
- The DFIR Report

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
  server.js                  Small Node.js static/API server with read-only telemetry and pipeline health

scripts/
  generate_threat_intel.py   Fetches and formats daily intelligence
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

Start the dashboard:

```bash
node dashboard/server.js
```

Open:

```text
http://localhost:8765
```

The landing page is a read-only resource monitor for the host running the pipeline. It includes threshold-based health status and the last telemetry update time. Threat intelligence views are available in the navigation.

## Configuration

The default layout works from the repository root. These environment variables can override paths and network settings:

```bash
COCKY_DASHBOARD_HOST=0.0.0.0
COCKY_DASHBOARD_PORT=8765
THREAT_INTEL_ROOT=/path/to/repo
THREAT_INTEL_DASHBOARD_DIR=/path/to/repo/dashboard
THREAT_INTEL_OUTPUT=/path/to/discoveries-generated.json
THREAT_INTEL_DISCOVERIES=/path/to/discoveries.json
THREAT_INTEL_INBOX=/path/to/discoveries-inbox.json
THREAT_INTEL_PIPELINE_HEALTH=/path/to/pipeline-health.json
THREAT_INTEL_SYSTEM_URL=http://remote-host:8765/api/system
THREAT_INTEL_DISCOVERIES_URL=http://remote-host:8765/api/discoveries
THREAT_INTEL_PIPELINE_URL=http://remote-host:8765/api/pipeline
```

When running the dashboard locally but displaying a remote homelab node, set
`THREAT_INTEL_SYSTEM_URL`, `THREAT_INTEL_DISCOVERIES_URL`, and
`THREAT_INTEL_PIPELINE_URL` to the remote dashboard API endpoints.

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
- RSS research entries are filtered by security keywords to avoid conference, interview, or general technology content.
- Existing entries with the same date and title are updated instead of duplicated.
