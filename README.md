# 🎯 BBOT MCP Server

A comprehensive Model Context Protocol (MCP) server implementation that provides programmatic access to BBOT (Bighuge BLS OSINT Tool) for security reconnaissance operations.

## 📋 Overview

**BBOT MCP Server** wraps the powerful BBOT reconnaissance framework in an MCP interface, enabling AI assistants to orchestrate complex security assessments through Claude Code.

### 🔑 Key Features

- **Comprehensive Reconnaissance**: Subdomain enumeration, network scanning, web application testing
- **140+ Modules**: Specialized tools for DNS, HTTP, cloud, and advanced vulnerability detection
- **Flexible Presets**: Predefined scan configurations for different reconnaissance needs
- **MCP Integration**: Seamless integration with Claude Code and other AI assistants
- **Real-time Monitoring**: Live status updates and result streaming
- **Production Ready**: Comprehensive test suite and error handling

## 🏗️ Project Structure

```
BBOT-MCP/
├── mcp_server/           # Core MCP server implementation
│   ├── __init__.py        # Package initialization
│   ├── scanner.py         # BBOT process management
│   ├── bbot_server.py     # FastMCP server with tools
│   ├── __main__.py        # Entry point for running server
│   └── docs/              # Documentation generation utilities
│       ├── __init__.py
│       ├── openapi_template.py
│       └── generate_markdown.py
│
├── tests/                # Test suite
│   ├── e2e/              # End-to-end tests
│   │   └── test_bbot_mcp_server.py
│   ├── fixtures.py        # Test data fixtures
│   └── utils.py           # Test utilities
│
├── docs/                 # Documentation
│   ├── API.md            # API reference
│   ├── QUICK_START.md    # Quick start guide
│   └── CONTRIBUTING.md   # Contribution guidelines
│
├── scan_outputs/         # Runtime scan output directory
├── start_bbot_mcp.sh     # Bash script to start server
├── CHANGELOG.md          # Version history
└── README.md             # This file
```

## 🚀 Quick Start

### 1. Start the Server

```bash
# Method 1: Using the startup script (recommended)
./start_bbot_mcp.sh

# Method 2: Direct execution
python -m mcp_server
```

### 2. Use with Claude Code

```bash
# In a Claude Code session with MCP enabled
# The server will automatically register these tools:

# Start a reconnaissance scan
/start_scan(
    targets=["example.com"],
    presets=["subdomain-enum"],
    modules=["http", "portscan"]
)

# Check scan status
/get_scan_status("scan_abc123")

# List scan findings
/list_findings("scan_abc123", limit=10)

# List all active scans
/list_scans()
```

### 3. Access API Documentation

- **OpenAPI JSON**: `http://localhost:8080/docs/openapi.json`
- **Swagger UI**: `http://localhost:8080/docs` (when FastAPI server is enabled)

## 🛠️ Available Tools

| Tool | Description | Parameters |
|------|-------------|------------|
| `start_scan` | Execute a new BBOT reconnaissance scan | targets, presets, modules, scan_name, timeout |
| `get_scan_status` | Get status of a running or completed scan | scan_id |
| `list_findings` | Retrieve findings from a scan | scan_id, limit, event_type |
| `list_scans` | List all active scans | - |
| `get_scan_details` | Get detailed information about a specific scan | scan_id |
| `cancel_scan` | Cancel a running scan | scan_id |
| `get_scan_output` | Get raw output from a completed scan | scan_id |
| `docs` | Generate OpenAPI documentation | - |

## 🎨 BBOT Presets

| Preset | Description | # Modules |
|--------|-------------|-----------|
| `subdomain-enum` | Enumerate subdomains | 51 |
| `web-basic` | Quick web scan | 18 |
| `web-thorough` | Aggressive web scan | 32 |
| `portscan` | Discover open ports | 2 |
| `cloud-enum` | Enumerate cloud resources | 58 |
| `kitchen-sink` | Everything everywhere all at once | 90 |
| `nuclei` | Run nuclei vulnerability scans | 3 |

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Server host | `localhost` |
| `PORT` | Server port | `8080` |
| `OPENROUTER_API_KEY` | API key for OpenRouter | - |
| `ANTHROPIC_BASE_URL` | Custom API endpoint | `https://openrouter.ai/api` |

### Example Configuration

```bash
export HOST=0.0.0.0
export PORT=8080
export OPENROUTER_API_KEY=sk-or-v1-...

./start_bbot_mcp.sh
```

## 🧪 Testing

### Run End-to-End Tests

```bash
# Activate virtual environment
source venv/bin/activate

# Run all tests
python -m pytest tests/e2e/ -v

# Run specific test
python -m pytest tests/e2e/test_bbot_mcp_server.py::TestStartScanTool -v
```

### Test Coverage

- ✅ Server initialization and configuration
- ✅ Scan execution with various parameters
- ✅ Status monitoring and updates
- ✅ Findings retrieval
- ✅ Error handling and validation
- ✅ OpenAPI documentation generation

## 📖 Documentation

- [Quick Start Guide](docs/QUICK_START.md) - Getting started quickly
- [API Reference](docs/API.md) - Complete API documentation
- [Contributing Guide](docs/CONTRIBUTING.md) - How to contribute
- [Changelog](CHANGELOG.md) - Version history

## 🎓 Usage Examples

### Basic Subdomain Enumeration

```python
# Subdomain enumeration with default settings
result = await start_scan(["example.com"], ["subdomain-enum"])
# Returns: {"scan_id": "scan_abc123", "status": "in_progress"}
```

### Full Web Assessment

```python
# Comprehensive web scan including vulnerabilities
result = await start_scan(
    targets=["target.com"],
    presets=["kitchen-sink"],
    modules=["httpx", "nuclei", "gowitness"]
)
```

### Passive Recon Only

```python
# Passive reconnaissance only (no active connections)
result = await start_scan(
    targets=["example.com"],
    presets=["subdomain-enum"],
    modules=["passive"]
)
```

### Custom Scan Configuration

```python
# Advanced scan with custom settings
result = await start_scan(
    targets=["example.com", "api.example.com"],
    presets=["web-basic", "portscan"],
    modules=["httpx", "nuclei"],
    scan_name="my_custom_scan",
    timeout=600
)
```

## 🛡️ Security Notice

This tool is intended for authorized security testing only. Always obtain explicit permission before scanning any systems. The developers and contributors are not responsible for any misuse.

## 📜 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details.

## 📚 References

- [BBOT Documentation](https://github.com/4n6forntwin/BBOT)
- [MCP Documentation](https://github.com/modelcontextprotocol/python-sdk)
- [OpenRouter API](https://openrouter.ai/)