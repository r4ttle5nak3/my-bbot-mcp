---
name: bbot-recon
description: >-
  Orchestrate security reconnaissance scans using BBOT (Bighuge BLS OSINT Tool)
  through MCP tools. Covers subdomain enumeration, port scanning, web technology
  detection, cloud resource discovery, vulnerability scanning, and passive OSINT.
  Use when the user asks to enumerate, scan, recon, footprint, or gather
  intelligence on a target domain, IP, or organization.
metadata:
  author: r4ttle5nak3
  version: "1.0"
  source: https://github.com/r4ttle5nak3/my-bbot-mcp
---

# BBOT Recon Skill

Use this skill when the user asks to perform reconnaissance, footprinting, OSINT gathering, or security scanning against one or more targets **through the BBOT MCP server**. The server exposes BBOT as MCP tools — invoke them via the registered MCP tool names, not by constructing BBOT CLI commands directly.

## Prerequisites

- The BBOT MCP server must be running (`python -m mcp_server` from the project root).
- BBOT itself must be installed and available on `PATH`.
- The user must have authorization to scan the targets.

## Available MCP Tools

| Tool | Purpose |
|------|---------|
| `start_scan` | Start a new BBOT reconnaissance scan |
| `get_scan_status` | Check progress and runtime of a running scan |
| `list_findings` | Retrieve findings from a completed scan |
| `list_scans` | List all active scans |
| `get_scan_details` | Get detailed scan configuration and timing |
| `cancel_scan` | Stop a running scan |
| `get_scan_output` | Get raw BBOT CLI output |
| `validate_scan_config` | Validate parameters before starting a scan |

## Workflow

### 1. Understand the Objective

Determine what the user wants:

- **Subdomain enumeration** → `subdomain-enum` preset
- **Web technology detection** → `tech-detect` preset
- **Port scanning** → `portscan` preset + `fingerprintx` module
- **Cloud resource discovery** → `cloud-enum` preset
- **Vulnerability scanning** → `nuclei` preset
- **Full web assessment** → `web-basic` or `web-thorough` preset
- **Web spidering** → `spider` or `spider-intense` preset
- **Everything** → `kitchen-sink` preset
- **Passive-only** → `subdomain-enum` preset with `-rf passive` flag equivalent
- **Code/secret enumeration** → `code-enum` preset
- **Email enumeration** → `email-enum` preset

### 2. Plan the Scan

Select the appropriate preset(s) and optionally list additional modules.

**Preset selection guidance:**

| Use Case | Preset | Modules | Notes |
|----------|--------|---------|-------|
| Quick subdomain discovery | `subdomain-enum` | 51 | Good starting point for any target |
| Fast passive recon | `subdomain-enum` | 51 | Add `--rf passive` style flag via config |
| Web tech + basic vulns | `web-basic` | 18 | Non-intrusive |
| Full web assessment | `web-thorough` | 32 | Aggressive — includes fuzzing, SSRF checks |
| Open ports | `portscan` | 2 | Fast, lightweight |
| Cloud buckets | `cloud-enum` | 58 | AWS, GCP, Azure, DigitalOcean |
| Web screenshots | `web-screenshots` | 3 | Visual recon |
| Vulnerability scan | `nuclei` | 3 | Template-based vuln detection |
| Web spider | `spider` | 1 | Follows links recursively |
| Technology detection | `tech-detect` | 3 | FingerprintX + nuclei |
| Web fuzzing | `dirbust-light` | 4 | Non-recursive directory brute-force |
| Web fuzzing (deep) | `dirbust-heavy` | 5 | Recursive directory brute-force |
| IIS/.NET audit | `dotnet-audit` | 9 | Specialized for IIS targets |
| Everything | `kitchen-sink` | 90 | Very noisy and slow |
| Parameter discovery | `paramminer` | 6 | Cookie, GET, and header params |
| Light fuzzing | `lightfuzz-medium` | 6 | Good default for web vuln discovery |
| XSS-focused fuzzing | `lightfuzz-xss` | 5 | GET-based XSS detection |

**Common additional modules to append:**

- `httpx` — HTTP service probing and tech detection (included in many presets)
- `nuclei` — vulnerability template matching
- `gowitness` — web page screenshots
- `fingerprintx` — service fingerprinting (SSH, MySQL, RDP, etc.)
- `dnsbrute` — subdomain brute-force (aggressive)
- `ffuf` — web fuzzing (deadly)
- `smuggler` — HTTP request smuggling detection
- `wafw00f` — WAF detection
- `trufflehog` — secret scanning in git repos
- `hunt` — advanced web vulnerability hunting
- `bypass403` — 403 bypass testing
- `generic_ssrf` — SSRF vulnerability detection

### 3. Start the Scan

Use `start_scan` with the planned parameters:

```python
# Basic subdomain enumeration
result = await start_scan(
    targets=["example.com"],
    presets=["subdomain-enum"]
)

# Full web assessment with screenshots
result = await start_scan(
    targets=["target.com", "api.target.com"],
    presets=["web-thorough"],
    modules=["gowitness", "nuclei"],
    scan_name="full_recon_2024",
    timeout=600
)

# Passive-only recon
result = await start_scan(
    targets=["example.com"],
    presets=["subdomain-enum"]
    # Note: passivity is achieved by requiring passive-only flags
    # via the BBOT CLI (not directly exposed as a parameter yet)
)

# Validate first, then start
validation = await validate_scan_config({
    "targets": ["example.com"],
    "presets": ["subdomain-enum"],
    "modules": ["nuclei"]
})
if validation["valid"]:
    result = await start_scan(
        targets=["example.com"],
        presets=["subdomain-enum"],
        modules=["nuclei"]
    )
```

The response includes a `scan_id` — save it for status checks and result retrieval.

### 4. Monitor Progress

Poll `get_scan_status` to check if the scan is still running:

```python
status = await get_scan_status("scan_abc123")
# Returns: {"scan_id": "...", "status": "in_progress|completed|not_found",
#            "runtime": "0h 2m 15s", "targets": [...], "command": "..."}
```

List all active scans at any time:

```python
scans = await list_scans()
# Returns: [{"scan_id": "...", "status": "...", "targets": [...], "started": "..."}]
```

### 5. Retrieve Results

Once the scan is complete, get findings:

```python
findings = await list_findings(
    scan_id="scan_abc123",
    limit=20,
    event_type="DNS_NAME"  # optional filter
)
```

For detailed scan info including configuration and timing:

```python
details = await get_scan_details("scan_abc123")
```

For raw BBOT output:

```python
output = await get_scan_output("scan_abc123")
```

### 6. Cancel if Needed

If a scan is taking too long or was started in error:

```python
result = await cancel_scan("scan_abc123")
```

## Common Scan Patterns

### Pattern 1: Quick Subdomain Discovery (Passive)

```python
scan = await start_scan(targets=["example.com"], presets=["subdomain-enum"])
# Wait for completion...
findings = await list_findings(scan["scan_id"], limit=50)
```

### Pattern 2: Subdomains + Ports + Screenshots

```python
scan = await start_scan(
    targets=["example.com"],
    presets=["subdomain-enum"],
    modules=["portscan", "gowitness"],
    timeout=600
)
```

### Pattern 3: Cloud Resource Discovery

```python
scan = await start_scan(
    targets=["example.com"],
    presets=["cloud-enum"],
    modules=["bucket_amazon", "bucket_google", "bucket_microsoft"]
)
```

### Pattern 4: Vulnerability Scanning

```python
scan = await start_scan(
    targets=["example.com"],
    presets=["subdomain-enum", "web-basic"],
    modules=["nuclei"],
    timeout=900
)
```

### Pattern 5: Deep Web Application Audit

```python
scan = await start_scan(
    targets=["app.example.com"],
    presets=["web-thorough"],
    modules=["nuclei", "gowitness", "smuggler", "wafw00f"],
    scan_name="deep_audit",
    timeout=1200
)
```

### Pattern 6: Technology Stack Detection

```python
scan = await start_scan(
    targets=["example.com"],
    presets=["tech-detect"],
    modules=["wafw00f"]
)
```

### Pattern 7: Code Repository and Secret Discovery

```python
scan = await start_scan(
    targets=["example.com"],
    presets=["code-enum"],
    modules=["trufflehog", "git"],
    timeout=600
)
```

## Safety Considerations

1. **Authorization**: Always confirm the user owns the target or has explicit written permission to scan it.
2. **Aggressiveness**: `kitchen-sink`, `web-thorough`, `dirbust-heavy`, and `lightfuzz-*` presets generate significant traffic and may trigger WAFs/IDS. Start with `subdomain-enum` or `web-basic` for an initial assessment.
3. **Deadly modules**: `ffuf`, `legba`, `lightfuzz`, `medusa`, `nuclei`, and `vhost` are flagged as `deadly` — they are highly aggressive. Use with caution.
4. **Rate limiting**: BBOT has built-in rate limiting, but aggressive scans on small targets can still overwhelm services.
5. **Data storage**: Scan outputs are saved to `scan_outputs/` in the project directory. Respect data retention policies.
6. **Passive first**: Start with passive-only reconnaissance (`subdomain-enum` without aggressive modules) before escalating to active scanning.

## Output Interpretation

### Event Types

BBOT produces various event types in its findings:

| Event Type | Meaning |
|------------|---------|
| `DNS_NAME` | Discovered domain/subdomain |
| `IP_ADDRESS` | Resolved IP address |
| `OPEN_TCP_PORT` | Open port on a target |
| `URL` | Discovered URL |
| `HTTP_RESPONSE` | HTTP response data |
| `FINDING` | Generic finding |
| `VULNERABILITY` | Security vulnerability |
| `TECHNOLOGY` | Detected technology/stack |
| `STORAGE_BUCKET` | Cloud storage bucket |
| `CODE_REPOSITORY` | Discovered code repo |
| `EMAIL_ADDRESS` | Discovered email |
| `WEBSCREENSHOT` | Web page screenshot reference |
| `PROTOCOL` | Identified service protocol |

### What to Report to the User

- **Subdomains discovered** — list the most interesting ones (admin panels, dev environments, API endpoints)
- **Open ports and services** — especially non-standard ports or unexpected services
- **Technologies detected** — web server, framework, CMS, analytics
- **Vulnerabilities found** — severity, affected endpoint, CVSS if available
- **Cloud resources** — exposed storage buckets, open databases
- **Leaked credentials/secrets** — from code repositories
- **Screenshots** — visual confirmation of web properties

## Troubleshooting

| Problem | Likely Cause | Solution |
|---------|-------------|----------|
| `Scan not found` | Wrong scan_id | List active scans with `list_scans` |
| Scan stuck "in_progress" | BBOT process hung | Cancel with `cancel_scan`, retry |
| No findings returned | Scan may still be running | Check `get_scan_status` first |
| `Invalid configuration` | Bad target format | Use valid domain, IPv4, or hostname |
| `Unknown preset` | Typo in preset name | Check [presets reference](references/PRESETS.md) |
| `Disallowed module` | Module not in allowlist | Use one of the allowed modules |

## Reference Files

For detailed reference material, see:

- [Presets Reference](references/PRESETS.md) — all BBOT presets with descriptions
- [Modules Reference](references/MODULES.md) — all BBOT scan modules with flags
- [Flags Reference](references/FLAGS.md) — all BBOT flags with module lists