# BBOT MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that wraps [BBOT](https://github.com/blacklanternsecurity/bbot) (Bighuge BLS OSINT Tool) — the modular reconnaissance framework from Black Lantern Security — into MCP tools for AI assistants.

[![BBOT Documentation](https://img.shields.io/badge/BBOT-Docs-blue)](https://www.blacklanternsecurity.com/bbot/Stable/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

**BBOT MCP Server** exposes BBOT's reconnaissance capabilities through the MCP protocol, allowing AI agents to orchestrate subdomain enumeration, port scanning, web technology detection, cloud resource discovery, and vulnerability scanning — all through natural language or tool calls.

### Key Features

- **140+ BBOT modules** — DNS, HTTP, cloud, vulnerability detection, and more
- **Flexible presets** — `subdomain-enum`, `web-thorough`, `kitchen-sink`, `nuclei`, and 20+ others
- **MCP-native** — tools register automatically with any MCP client (Claude Code, Hermes Agent, etc.)
- **Async monitoring** — scans run in the background with real-time status updates
- **Configurable presets** — add custom presets through config files without code changes

---

## Quick Start

### Prerequisites

- Python 3.8+
- [BBOT](https://github.com/blacklanternsecurity/bbot) installed (`pip install bbot` or from source)

### 1. Install

```bash
git clone <your-repo>
cd my-bbot-mcp
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Start the Server

```bash
# Method 1: Startup script
./start_bbot_mcp.sh

# Method 2: Direct
python -m mcp_server
```

### 3. Available Tools

Once running, the server registers these MCP tools:

| Tool | Description |
|------|-------------|
| `start_scan` | Start a BBOT reconnaissance scan |
| `get_scan_status` | Check scan progress and runtime |
| `list_findings` | Retrieve scan results |
| `list_scans` | List all active scans |
| `get_scan_details` | Detailed scan info (config, timing) |
| `cancel_scan` | Stop a running scan |
| `get_scan_output` | Get raw BBOT output |
| `validate_scan_config` | Validate params before starting |

---

## Integration Guides

### Claude Code

Claude Code supports MCP servers natively. Point it at this server in your MCP configuration:

**`~/.claude/settings.json` or project `.claude/settings.json`:**

```json
{
  "mcpServers": {
    "bbot": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/my-bbot-mcp"
    }
  }
}
```

Then in a Claude Code session:

```
# Start a subdomain scan
start_scan({"targets": ["example.com"]})

# Check findings once it's done
list_findings({"scan_id": "scan_abc123", "limit": 20})
```

Claude Code will see the available tools automatically and suggest them as you work.

### Hermes Agent

[Hermes Agent](https://github.com/NVIDIA/agentic-coder) supports MCP tools through its configuration. Add the server to your Hermes MCP config:

```json
{
  "mcpServers": {
    "bbot": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/my-bbot-mcp"
    }
  }
}
```

When Hermes loads, it connects to the MCP server, discovers the registered tools, and can invoke them during reconnaissance tasks. The agent will call `start_scan`, `get_scan_status`, and `list_findings` as part of its workflow.

### Any MCP Client

The server uses the standard MCP transport (stdio by default). Any MCP-compatible client can connect:

- **Claude Desktop** — add to `claude_desktop_config.json`
- **VS Code extension** — configure in extension settings
- **Custom client** — use the [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) to connect

---

## Usage Examples

### Basic Subdomain Enumeration

```python
result = await start_scan(targets=["example.com"])
# {"scan_id": "scan_abc123", "status": "in_progress", "message": "Scan started successfully"}
```

### Full Web Assessment

```python
result = await start_scan(
    targets=["target.com"],
    presets=["kitchen-sink"],
    modules=["httpx", "nuclei", "gowitness"],
    scan_name="full_recon_2024",
    timeout=600
)
```

### Passive Reconnaissance Only

```python
# No active connections to the target
result = await start_scan(
    targets=["example.com"],
    presets=["subdomain-enum"],
    modules=["passive"]
)
```

### Check Status and Get Results

```python
status = await get_scan_status("scan_abc123")
# {"scan_id": "scan_abc123", "status": "in_progress", "runtime": "0h 2m 15s", ...}

findings = await list_findings("scan_abc123", limit=10)
# {"scan_id": "scan_abc123", "findings": [...], "count": 10}
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Server host | `localhost` |
| `PORT` | Server port | `8080` |

### JSON Config File

Place a config file at `mcp_server/config/server.json` to override defaults:

```json
{
  "scan": {
    "default_timeout": 600,
    "default_presets": ["subdomain-enum", "my-custom-preset"],
    "max_concurrent_scans": 5
  },
  "server": {
    "log_level": "DEBUG"
  }
}
```

### BBOT Presets

| Preset | Description | Modules |
|--------|-------------|---------|
| `subdomain-enum` | Enumerate subdomains | 51 |
| `web-basic` | Quick web scan | 18 |
| `web-thorough` | Aggressive web scan | 32 |
| `portscan` | Discover open ports | 2 |
| `cloud-enum` | Enumerate cloud resources | 58 |
| `kitchen-sink` | Everything at once | 90 |
| `nuclei` | Run nuclei vulnerability scans | 3 |
| `spider` | Recursive web spider | 1 |
| `tech-detect` | Detect technologies | 3 |

Full reference: [BBOT Documentation](https://www.blacklanternsecurity.com/bbot/Stable/)

---

## Project Structure

```
my-bbot-mcp/
├── mcp_server/              # Core MCP server
│   ├── bbot_server.py       # FastMCP server with tools
│   ├── scanner.py           # BBOT subprocess management
│   ├── __init__.py          # Package init
│   └── __main__.py          # Entry point
├── tests/                   # Test suite
│   ├── e2e/                 # End-to-end tests
│   ├── fixtures.py          # Test data and mocks
│   └── utils.py             # Test utilities
├── docs/                    # Documentation
│   ├── API.md
│   ├── QUICK_START.md
│   └── CONTRIBUTING.md
├── requirements.txt         # Python dependencies
└── README.md
```

---

## Testing

```bash
source venv/bin/activate
python -m pytest tests/ -v
```

---

## Security Notice

This tool is intended for **authorized security testing only**. Always obtain explicit written permission before scanning any systems you do not own. The authors and contributors are not responsible for misuse.

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## References

- [BBOT Documentation](https://www.blacklanternsecurity.com/bbot/Stable/)
- [BBOT GitHub](https://github.com/blacklanternsecurity/bbot)
- [MCP Protocol](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)