# BBOT Presets Reference

BBOT presets are pre-configured module combinations for common reconnaissance tasks. Use them as the `presets` parameter in `start_scan`.

## General Presets

| Preset | Description | Modules | Use Case |
|--------|-------------|---------|----------|
| `subdomain-enum` | Enumerate subdomains via APIs, brute-force | 51 | Starting point for any target |
| `kitchen-sink` | Everything everywhere all at once | 90 | Full-spectrum recon (very noisy) |
| `fast` | Scan only provided targets, no extra discovery | 0 | Quick check against known targets |
| `cloud-enum` | Enumerate cloud resources (buckets, etc.) | 58 | Cloud asset discovery |
| `code-enum` | Enumerate Git repos, Docker images, etc. | 20 | Source code and secret discovery |
| `email-enum` | Enumerate email addresses | 8 | OSINT email gathering |
| `tech-detect` | Detect technologies via Nuclei and FingerprintX | 3 | Technology stack fingerprinting |
| `spider` | Recursive web spider | 1 | Site crawling and link discovery |
| `spider-intense` | Recursive web spider with aggressive settings | 1 | Deep site crawling |
| `portscan` | Discover open ports | 2 | Port scanning |
| `web-screenshots` | Take screenshots of webpages | 3 | Visual recon |
| `baddns-intense` | Run all baddns modules and submodules | 4 | DNS takeover detection |

## Web Presets

| Preset | Description | Modules | Aggressiveness |
|--------|-------------|---------|----------------|
| `web-basic` | Quick web scan (non-intrusive) | 18 | Low |
| `web-thorough` | Aggressive web scan | 32 | High |
| `dirbust-light` | Basic web directory brute-force | 4 | Medium |
| `dirbust-heavy` | Recursive web directory brute-force | 5 | High |
| `iis-shortnames` | Recursively enumerate IIS shortnames | 3 | Medium |
| `dotnet-audit` | Comprehensive IIS/.NET scan | 9 | High |
| `paramminer` | Discover web parameters via brute-force | 6 | Medium |
| `lightfuzz-light` | Minimal web fuzzing, safest option | 3 | Low |
| `lightfuzz-medium` | Default web fuzzing (good starting point) | 6 | Medium |
| `lightfuzz-heavy` | Heavy web fuzzing with POST params | 10 | High |
| `lightfuzz-superheavy` | Most intense web fuzzing | 10 | Very High |
| `lightfuzz-xss` | XSS-focused GET-based fuzzing | 5 | Medium |

## Nuclei Presets

| Preset | Description | Modules | Notes |
|--------|-------------|---------|-------|
| `nuclei` | Run nuclei against all discovered targets | 3 | Full template matching |
| `nuclei-budget` | Budget mode — low-hanging fruit only | 3 | Reduced request count |
| `nuclei-intense` | Intensive nuclei with spidering | 6 | Includes spidering + wayback |
| `nuclei-technology` | Technology-matched templates only | 3 | Faster, targeted |

## Preset Category Legend

Presets belong to categories that affect their behavior:

- **web** — Web application scanning presets (directory busting, fuzzing, parameter mining)
- **nuclei** — Vulnerability scanning presets using the Nuclei engine
- *(no category)* — General reconnaissance presets

## Usage Tips

- Combine presets: `presets: ["subdomain-enum", "web-basic"]` runs both simultaneously.
- Append modules to a preset for extra coverage: `presets: ["subdomain-enum"], modules: ["nuclei"]`.
- For passive-only scans, use `subdomain-enum` and avoid aggressive modules like `dnsbrute`, `ffuf`, or `portscan`.
- Start with `subdomain-enum` or `web-basic` before escalating to `kitchen-sink` or `web-thorough`.
- `fast` preset disables all extra discovery — useful for scanning a specific list of known targets.