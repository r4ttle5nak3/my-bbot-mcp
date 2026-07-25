# BBOT Flags Reference

BBOT flags categorize modules by their behavior, aggressiveness, and purpose. Use flag filters to control which modules are enabled during a scan.

## Flag Categories

| Flag | # Modules | Description |
|------|-----------|-------------|
| `safe` | 98 | Non-intrusive, safe to run |
| `passive` | 70 | Never connects to target systems |
| `active` | 52 | Makes active connections to target systems |
| `subdomain-enum` | 51 | Enumerates subdomains |
| `aggressive` | 22 | Generates large amount of network traffic |
| `code-enum` | 18 | Finds public code repositories and searches for secrets |
| `web-basic` | 17 | Basic, non-intrusive web scan functionality |
| `cloud-enum` | 16 | Enumerates cloud resources |
| `web-thorough` | 15 | More advanced web scanning functionality |
| `slow` | 11 | May take a long time to complete |
| `email-enum` | 9 | Enumerates email addresses |
| `affiliates` | 8 | Discovers affiliated hostnames/domains |
| `download` | 7 | Modules that download files, apps, or repositories |
| `deadly` | 6 | Highly aggressive |
| `baddns` | 3 | DNS auditing (BadDNS) |
| `web-paramminer` | 3 | HTTP parameter brute-force |
| `iis-shortnames` | 2 | IIS Shortname vulnerability scanning |
| `portscan` | 2 | Discovers open ports |
| `social-enum` | 2 | Enumerates social media |
| `service-enum` | 1 | Identifies protocols on open ports |
| `subdomain-hijack` | 1 | Detects hijackable subdomains |
| `web-screenshots` | 1 | Takes screenshots of web pages |

## Flag Usage in BBOT CLI

While the MCP server doesn't directly expose flag filtering as a parameter, you can achieve similar effects by choosing the right preset and module combination:

### Passive-Only Recon (no connections to target)

Use `subdomain-enum` preset and avoid adding active modules like `dnsbrute`, `portscan`, `ffuf`, `nuclei`, `gowitness`. The `subdomain-enum` preset predominantly uses passive sources.

### Safe-Only Scan

Combine `web-basic` or `subdomain-enum` presets. Avoid aggressive modules and deadly modules.

### Aggressive Scan

Use `kitchen-sink` or `web-thorough` presets, or add `--allow-deadly` equivalent by explicitly including deadly modules like `nuclei`, `ffuf`, `lightfuzz`.

## Flag-to-Preset Mapping

### Modules by Flag (for advanced filtering)

**Passive modules** (70 total) — never connect to the target:
`affiliates`, `anubisdb`, `apkpure`, `asn`, `azure_realm`, `azure_tenant`, `bevigil`, `bucket_file_enum`, `bufferoverrun`, `builtwith`, `c99`, `censys_dns`, `censys_ip`, `certspotter`, `chaos`, `code_repository`, `credshed`, `crt`, `crt_db`, `dehashed`, `digitorus`, `dnsbimi`, `dnscaa`, `dnsdumpster`, `dnstlsrpt`, `docker_pull`, `dockerhub`, `emailformat`, `extractous`, `fullhunt`, `git_clone`, `gitdumper`, `github_codesearch`, `github_org`, `github_usersearch`, `github_workflows`, `google_playstore`, `hackertarget`, `hunterio`, `ip2location`, `ipneighbor`, `ipstack`, `jadx`, `leakix`, `myssl`, `otx`, `passivetotal`, `pgp`, `portfilter`, `postman`, `postman_download`, `rapiddns`, `securitytrails`, `shodan_dns`, `shodan_idb`, `sitedossier`, `skymem`, `social`, `sslcert`, `subdomaincenter`, `subdomainradar`, `trickest`, `trufflehog`, `urlscan`, `viewdns`, `virustotal`, `wayback`

**Active modules** (52 total) — make connections to the target:
`ajaxpro`, `aspnet_bin_exposure`, `baddns`, `baddns_direct`, `baddns_zone`, `badsecrets`, `bucket_amazon`, `bucket_digitalocean`, `bucket_firebase`, `bucket_google`, `bucket_microsoft`, `bypass403`, `dnsbrute`, `dnsbrute_mutations`, `dnscommonsrv`, `dotnetnuke`, `ffuf`, `ffuf_shortnames`, `filedownload`, `fingerprintx`, `generic_ssrf`, `git`, `gitlab_com`, `gitlab_onprem`, `gowitness`, `graphql_introspection`, `host_header`, `httpx`, `hunt`, `iis_shortnames`, `legba`, `lightfuzz`, `medusa`, `newsletters`, `ntlm`, `nuclei`, `oauth`, `paramminer_cookies`, `paramminer_getparams`, `paramminer_headers`, `portscan`, `reflected_parameters`, `retirejs`, `robots`, `securitytxt`, `smuggler`, `sslcert`, `telerik`, `url_manipulation`, `vhost`, `wafw00f`, `wpscan`

## Strategic Guidance

- **Start passive** — Use `subdomain-enum` first to understand the surface without alerting defensive teams.
- **Escalate safely** — Move to `web-basic` for low-noise HTTP probing, then to `web-thorough` only if the engagement allows.
- **Deadly last** — Modules flagged `deadly` (`ffuf`, `legba`, `lightfuzz`, `medusa`, `nuclei`, `vhost`) should only be used in clearly authorized aggressive engagements.
- **Know your flags** — `slow` modules (11 total) can dramatically increase scan time. Plan accordingly.