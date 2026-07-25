# BBOT Modules Reference

BBOT modules are individual scan components that perform specific reconnaissance tasks. Use them as the `modules` parameter in `start_scan` to extend a preset's capabilities.

## DNS & Subdomain Modules

| Module | Type | Flags | Description |
|--------|------|-------|-------------|
| `dnsbrute` | scan | active, aggressive, subdomain-enum | Brute-force subdomains with massdns + static wordlist |
| `dnsbrute_mutations` | scan | active, aggressive, slow, subdomain-enum | Brute-force subdomains with target-specific mutations |
| `dnscommonsrv` | scan | active, safe, subdomain-enum | Check for common SRV records |
| `dnscaa` | scan | active, safe, subdomain-enum | CAA record checking |
| `dnsbimi` | scan | active, safe, subdomain-enum | BIMI record checking |
| `dnstlsrpt` | scan | active, safe, subdomain-enum | TLS reporting record checking |
| `massdns` | scan | — | High-performance DNS resolution |

## API & Intelligence Sources

| Module | Type | API Key? | Flags | Description |
|--------|------|----------|-------|-------------|
| `anubisdb` | scan | No | passive, safe, subdomain-enum | AnubisDB subdomain database |
| `bevigil` | scan | No | passive, safe, subdomain-enum | BeVigil OSINT subdomain source |
| `bufferoverrun` | scan | No | passive, safe, subdomain-enum | BufferOver.run subdomain source |
| `builtwith` | scan | No | passive, safe, subdomain-enum | BuiltWith technology lookup |
| `c99` | scan | No | passive, safe, subdomain-enum | c99 subdomain API |
| `censys_dns` | scan | No | passive, safe, subdomain-enum | Censys DNS data |
| `censys_ip` | scan | No | passive, safe, subdomain-enum | Censys IP data |
| `certspotter` | scan | No | passive, safe, subdomain-enum | Certificate Transparency logs |
| `chaos` | scan | No | passive, safe, subdomain-enum | Project Chaos dataset |
| `crt` | scan | No | passive, safe, subdomain-enum | crt.sh Certificate Transparency |
| `crt_db` | scan | No | passive, safe, subdomain-enum | Local crt.sh database |
| `digitorus` | scan | No | passive, safe, subdomain-enum | Digitorus subdomain API |
| `fullhunt` | scan | No | passive, safe, subdomain-enum | FullHunt API |
| `hackertarget` | scan | No | passive, safe, subdomain-enum | HackerTarget API |
| `hunterio` | scan | No | passive, safe, subdomain-enum | Hunter.io email/subdomain API |
| `leakix` | scan | No | passive, safe, subdomain-enum | LeakIX data |
| `otx` | scan | No | passive, safe, subdomain-enum | AlienVault OTX |
| `passivetotal` | scan | No | passive, safe, subdomain-enum | PassiveTotal API |
| `rapiddns` | scan | No | passive, safe, subdomain-enum | RapidDNS subdomain source |
| `securitytrails` | scan | No | passive, safe, subdomain-enum | SecurityTrails API |
| `shodan_dns` | scan | No | passive, safe, subdomain-enum | Shodan DNS data |
| `shodan_idb` | scan | No | passive, safe, subdomain-enum | Shodan Internet DB |
| `sitedossier` | scan | No | passive, safe, subdomain-enum | SiteDossier subdomain source |
| `subdomaincenter` | scan | No | passive, safe, subdomain-enum | SubdomainCenter API |
| `subdomainradar` | scan | No | passive, safe, subdomain-enum | SubdomainRadar API |
| `trickest` | scan | No | passive, safe, subdomain-enum | Trickest workflow data |
| `urlscan` | scan | No | passive, safe, subdomain-enum | URLScan.io data |
| `viewdns` | scan | No | passive, safe, subdomain-enum | ViewDNS reverse whois |
| `virustotal` | scan | No | passive, safe, subdomain-enum | VirusTotal data |
| `wayback` | scan | No | passive, safe, subdomain-enum | Wayback Machine CDX |

## Web Scanning Modules

| Module | Type | Flags | Description |
|--------|------|-------|-------------|
| `httpx` | scan | active, safe, web-basic, web-thorough, ... | HTTP service probing and tech detection |
| `ffuf` | scan | active, aggressive, deadly | Fast web fuzzer (Go) |
| `ffuf_shortnames` | scan | active, aggressive, iis-shortnames, web-thorough | IIS shortname fuzzing |
| `iis_shortnames` | scan | active, safe, web-basic | IIS shortname enumeration |
| `robots` | scan | active, safe, web-basic | robots.txt parsing |
| `securitytxt` | scan | active, safe, web-basic | security.txt discovery |
| `vhost` | scan | active, aggressive, deadly | Virtual host brute-force |
| `smuggler` | scan | active, aggressive, web-thorough | HTTP request smuggling |
| `host_header` | scan | active, aggressive, web-thorough | Host header injection testing |
| `bypass403` | scan | active, aggressive, web-thorough | 403 bypass techniques |
| `url_manipulation` | scan | active, aggressive, web-thorough | URL manipulation testing |
| `generic_ssrf` | scan | active, aggressive, web-thorough | SSRF vulnerability detection |
| `hunt` | scan | active, safe, web-thorough | Advanced web vulnerability hunting |
| `reflected_parameters` | scan | active, safe, web-thorough | Reflected parameter detection |
| `lightfuzz` | scan | active, aggressive, deadly | Lightweight web fuzzer |
| `paramminer_cookies` | scan | active, aggressive, slow | Cookie parameter brute-force |
| `paramminer_getparams` | scan | active, aggressive, slow | GET parameter brute-force |
| `paramminer_headers` | scan | active, aggressive, slow | Header parameter brute-force |
| `filedownload` | scan | active, download, safe, web-basic | Download common filetypes (PDF, DOCX, etc.) |
| `wafw00f` | scan | active, safe | WAF detection |

## Technology & Fingerprinting

| Module | Type | Flags | Description |
|--------|------|-------|-------------|
| `fingerprintx` | scan | active, safe, service-enum, slow | Fingerprint exposed services (RDP, SSH, MySQL, etc.) |
| `wafw00f` | scan | active, safe | WAF detection |
| `retirejs` | scan | active, safe, web-thorough | JavaScript library vulnerability detection |
| `myssl` | scan | passive, safe, subdomain-enum | SSL/TLS configuration analysis |
| `sslcert` | scan | active, safe, subdomain-enum | SSL certificate gathering |
| `ntlm` | scan | active, safe, web-basic | NTLM authentication detection |
| `oauth` | scan | active, safe, web-basic | OAuth endpoint discovery |
| `ajaxpro` | scan | active, safe, web-thorough | Ajaxpro instance detection |
| `aspnet_bin_exposure` | scan | active, safe, web-thorough | ASP.NET binary exposure (CVE-2023-36899, CVE-2023-36560) |
| `dotnetnuke` | scan | active, aggressive, web-thorough | DotNetNuke vulnerability scanning |
| `telerik` | scan | active, aggressive, web-thorough | Telerik vulnerability scanning |
| `badsecrets` | scan | active, safe, web-basic | Known/weak secret detection across frameworks |
| `graphql_introspection` | scan | active, safe, web-basic | GraphQL introspection query |

## Cloud & Storage Modules

| Module | Type | Flags | Description |
|--------|------|-------|-------------|
| `bucket_amazon` | scan | active, cloud-enum, safe, web-basic | AWS S3 bucket discovery |
| `bucket_google` | scan | active, cloud-enum, safe, web-basic | Google Cloud Storage discovery |
| `bucket_microsoft` | scan | active, cloud-enum, safe, web-basic | Azure Blob Storage discovery |
| `bucket_digitalocean` | scan | active, cloud-enum, safe, slow, web-thorough | DigitalOcean Spaces discovery |
| `bucket_firebase` | scan | active, cloud-enum, safe, web-basic | Firebase database discovery |
| `bucket_file_enum` | scan | passive, safe, cloud-enum | Cloud bucket file enumeration |
| `azure_realm` | scan | active, safe, cloud-enum | Azure AD realm detection |
| `azure_tenant` | scan | active, safe, cloud-enum | Azure tenant discovery |

## Vulnerability & Security Modules

| Module | Type | Flags | Description |
|--------|------|-------|-------------|
| `nuclei` | scan | active, aggressive, deadly | Nuclei vulnerability template engine |
| `baddns` | scan | active, baddns, cloud-enum, safe, subdomain-hijack, web-basic | DNS takeover detection |
| `baddns_direct` | scan | active, baddns, cloud-enum, safe, subdomain-enum | Subdomain/service takeover edge cases |
| `baddns_zone` | scan | active, baddns, cloud-enum, safe, subdomain-enum | DNS zone transfer / NSEC walk |
| `smuggler` | scan | active, aggressive, web-thorough | HTTP request smuggling detection |
| `generic_ssrf` | scan | active, aggressive, web-thorough | SSRF vulnerability detection |
| `hunt` | scan | active, safe, web-thorough | Advanced web vulnerability hunting |

## Code & Repository Modules

| Module | Type | Flags | Description |
|--------|------|-------|-------------|
| `git` | scan | active, code-enum, safe, web-basic | Exposed .git repository detection |
| `git_clone` | scan | download, passive, safe, slow | Clone discovered git repos |
| `gitdumper` | scan | download, passive, safe, slow | Dump git repositories |
| `github_codesearch` | scan | passive, safe, subdomain-enum | GitHub code search |
| `github_org` | scan | passive, safe, subdomain-enum | GitHub organization enumeration |
| `github_usersearch` | scan | passive, safe | GitHub user search |
| `github_workflows` | scan | download, passive, safe | GitHub Actions workflow analysis |
| `gitlab_com` | scan | active, code-enum, safe | GitLab SaaS project enumeration |
| `gitlab_onprem` | scan | active, code-enum, safe | Self-hosted GitLab detection |
| `code_repository` | scan | passive, safe, code-enum | Code repository discovery |
| `trufflehog` | scan | passive, safe, code-enum | Secret scanning in git repos |
| `docker_pull` | scan | download, passive, slow, code-enum | Docker image pulling |
| `dockerhub` | scan | passive, safe, code-enum | Docker Hub enumeration |
| `postman` | scan | passive, safe, subdomain-enum | Postman workspace discovery |
| `postman_download` | scan | download, passive, safe, subdomain-enum | Postman collection download |
| `jadx` | scan | passive, safe, code-enum | APK decompilation |
| `apkpure` | scan | passive, safe, subdomain-enum | APKPure app enumeration |
| `google_playstore` | scan | passive, safe, code-enum | Google Play Store data |

## Social & OSINT Modules

| Module | Type | Flags | Description |
|--------|------|-------|-------------|
| `social` | scan | passive, safe, subdomain-enum | Social media discovery |
| `emailformat` | scan | passive, safe, subdomain-enum | Email address format detection |
| `pgp` | scan | passive, safe, subdomain-enum | PGP key server lookup |
| `skymem` | scan | passive, safe, subdomain-enum | SkyMem email database |
| `newsletters` | scan | active, safe | Newsletter subscription detection |
| `affiliates` | scan | passive, safe, affiliates | Affiliated hostname/domain discovery |
| `asn` | scan | passive, safe, subdomain-enum | ASN lookup |
| `ip2location` | scan | passive, safe, subdomain-enum | IP geolocation |
| `ipneighbor` | scan | passive, aggressive, subdomain-enum | IP neighbor discovery |
| `ipstack` | scan | passive, safe | IP geolocation via ipstack |
| `portfilter` | scan | passive, safe | Port filtering logic |

## Screenshot & Visual Modules

| Module | Type | Flags | Description |
|--------|------|-------|-------------|
| `gowitness` | scan | active, safe, web-screenshots | Web page screenshots |

## Module Type Legend

- **scan** — Standard reconnaissance module (the common type)
- **output** — Output/export module (see output modules reference)

## Usage Tips

- Modules are additive — you can append any module to any preset.
- Passive modules (flagged `passive` or `safe`) never connect to the target system.
- Deadly modules (`ffuf`, `legba`, `lightfuzz`, `medusa`, `nuclei`, `vhost`) are highly aggressive — use with caution.
- Cloud modules require internet access and may incur API costs.
- Some modules require API keys (e.g., `shodan_dns`, `censys_ip`, `builtwith`).