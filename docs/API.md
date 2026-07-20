# BBOT MCP Server API Reference

Complete API documentation for the BBOT MCP Server tools and endpoints.

## Table of Contents

- [Server Overview](#server-overview)
- [Tool Reference](#tool-reference)
  - [start_scan](#start_scan)
  - [get_scan_status](#get_scan_status)
  - [list_findings](#list_findings)
  - [list_scans](#list_scans)
  - [get_scan_details](#get_scan_details)
  - [cancel_scan](#cancel_scan)
  - [get_scan_output](#get_scan_output)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Authentication](#authentication)

---

## Server Overview

**Base URL:** `http://localhost:8080`  
**Protocol:** MCP (Model Context Protocol) via stdio or HTTP transport  
**Version:** 1.0.0

The server exposes several MCP tools that can be called programmatically via Claude Code or compatible MCP clients.

---

## Tool Reference

### start_scan

Execute a new BBOT reconnaissance scan.

#### Request

```python
await start_scan(
    targets: List[str],         # Required
    presets: Optional[List[str]], # Optional - default presets applied
    modules: Optional[List[str]], # Optional
    scan_name: Optional[str],    # Optional custom name
    timeout: Optional[int]      # Optional timeout in seconds
)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `targets` | `List[str]` | Yes | Target domains, IPs, or networks |
| `presets` | `List[str]` | No | BBOT presets (subdomain-enum, web-basic, etc.) |
| `modules` | `List[str]` | No | Specific modules to enable |
| `scan_name` | `str` | No | Custom scan identifier |
| `timeout` | `int` | No | Scan timeout (default: 300) |

#### Response

```json
{
  "scan_id": "scan_abc123def456",
  "status": "in_progress",
  "message": "Scan started successfully"
}
```

#### Example

```python
# Basic scan
result = await start_scan(["example.com"])

# Advanced scan
result = await start_scan(
    targets=["example.com", "api.example.com"],
    presets=["kitchen-sink"],
    modules=["httpx", "nuclei"],
    scan_name="full_assessment"
)
```

---

### get_scan_status

Get the current status of a running or completed scan.

#### Request

```python
await get_scan_status(scan_id: str)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scan_id` | `str` | Yes | Scan identifier from start_scan |

#### Response

```
Status: in_progress
Started: 2024-01-15 10:30:00
Runtime: 0h 2m 45s
Commands: python bbot_mcp.py -t example.com -p subdomain-enum
```

#### Example

```python
status = await get_scan_status("scan_abc123def456")
# Returns formatted status string
```

---

### list_findings

Retrieve findings from a completed scan.

#### Request

```python
await list_findings(
    scan_id: str,
    limit: Optional[int] = 10,
    event_type: Optional[str] = None
)
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scan_id` | `str` | Yes | Scan identifier |
| `limit` | `int` | No | Maximum findings to return (default: 10) |
| `event_type` | `str` | No | Filter by event type (DNS_NAME, HTTP_RESPONSE, etc.) |

#### Response

```json
{
  "findings": [
    "[DNS_NAME] subdomain1.example.com",
    "[OPEN_TCP_PORT] Port 443 is open",
    "[VULNERABILITY] CVE-2023-1234 detected"
  ],
  "count": 3,
  "scan_id": "scan_abc123def456"
}
```

#### Example

```python
findings = await list_findings("scan_abc123", limit=20)
# Returns findings with count
```

---

### list_scans

List all currently active scans.

#### Request

```python
await list_scans()
```

#### Response

```json
[
  {
    "scan_id": "scan_abc123",
    "status": "in_progress",
    "targets": ["example.com"],
    "started": "2024-01-15 10:30:00"
  },
  {
    "scan_id": "scan_def456",
    "status": "in_progress",
    "targets": ["test.com"],
    "started": "2024-01-15 10:35:00"
  }
]
```

---

### get_scan_details

Get detailed information about a specific scan.

#### Request

```python
await get_scan_details(scan_id: str)
```

#### Response

```json
{
  "scan_id": "scan_abc123",
  "status": "in_progress",
  "targets": ["example.com"],
  "presets": ["subdomain-enum"],
  "modules": ["httpx"],
  "scan_name": "custom_scan_name",
  "start_time": "2024-01-15 10:30:00",
  "duration_seconds": 150.5,
  "command": "python bbot_mcp.py -t example.com -p subdomain-enum",
  "output_path": "/path/to/output/scan_abc123.json"
}
```

---

### cancel_scan

Cancel a running scan.

#### Request

```python
await cancel_scan(scan_id: str)
```

#### Response

```json
{
  "status": "cancelled",
  "scan_id": "scan_abc123",
  "message": "Scan cancelled successfully"
}
```

---

### get_scan_output

Get the raw output from a completed scan.

#### Request

```python
await get_scan_output(scan_id: str)
```

#### Response

```json
{
  "scan_id": "scan_abc123",
  "status": "completed",
  "stdout": "Scan completed successfully...\n[INFO] Found 25 subdomains",
  "stderr": "",
  "duration": 150.5
}
```

---

## Error Handling

All tools follow a consistent error response format:

```json
{
  "error": "Descriptive error message",
  "details": ["Additional detail 1", "Additional detail 2"],
  "scan_id": "scan_abc123"  // if applicable
}
```

### Common Errors

| Error | Description | Solution |
|-------|-------------|----------|
| `Invalid configuration` | Missing or invalid parameters | Check required parameters |
| `No active scan found` | Scan ID doesn't exist | Verify scan_id is correct |
| `Scan execution failed` | BBOT process couldn't start | Check logs and permissions |

---

## Rate Limiting

The server implements the following limits:

- **Max concurrent scans**: 3 (configurable)
- **Scan timeout**: 300 seconds (configurable)
- **Max findings limit**: 100 per request (prevents memory issues)

---

## Authentication

No authentication is required for local operation. For remote deployment, consider:

1. Setting up reverse proxy with TLS
2. Adding authentication middleware
3. Restricting to VPN/internal network
4. Using environment variables for API keys

---

## OpenAPI Specification

The complete OpenAPI specification can be accessed at:

- JSON: `http://localhost:8080/docs/openapi.json`
- UI: `http://localhost:8080/docs` (Swagger UI)