# Quick Start Guide - BBOT MCP Server

Get up and running with the BBOT MCP Server in minutes.

## Prerequisites

- Python 3.8+ installed
- `pip` package manager
- Basic command-line familiarity

## One-Minute Setup

### 1. Clone and Install

```bash
# Clone the repository (or use your existing copy)
cd BBOT-MCP

# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install mcp
```

### 2. Configure Environment (Optional)

```bash
# Set your API key if needed
export OPENROUTER_API_KEY=sk-or-v1-...

# Or create .env file
cat > .env << 'EOF'
OPENROUTER_API_KEY=sk-or-v1-...
ANTHROPIC_BASE_URL=https://openrouter.ai/api
EOF
```

### 3. Start the Server

```bash
# Easy method
./start_bbot_mcp.sh

# Or manual method
python -m mcp_server
```

You should see:
```
Initializing BBOT MCP Server...
Server configuration: {'name': 'BBOT Recon MCP Server', ...}
```

### 4. Test in Claude Code

In a new Claude Code session:

```
/tools  # List available MCP tools
```

You should see the BBOT tools listed.

---

## Quick Usage Examples

### Basic Subdomain Scan

```python
# Find subdomains of a target
await start_scan(targets=["example.com"])

# Check the response
{
  "scan_id": "scan_abc123",
  "status": "in_progress",
  "message": "Scan started successfully"
}
```

### Check Status

```python
# Get real-time status
await get_scan_status("scan_abc123")

# Returns:
# Status: in_progress
# Started: 2024-01-15 10:30:00
# Runtime: 0h 0m 45s
```

### Get Results

```python
# After scan completes (or during)
await list_findings("scan_abc123", limit=20)

# Returns:
# {
#   "findings": ["[DNS_NAME] www.example.com", ...],
#   "count": 15
# }
```

### Comprehensive Scan

```python
# Full reconnaissance with all modules
await start_scan(
    targets=["target.com"],
    presets=["kitchen-sink"],  # All modules
    scan_name="full_recon_2024"
)
```

---

## Common Scan Presets

| Preset | Use Case |
|--------|----------|
| `subdomain-enum` | Find subdomains only (default) |
| `web-basic` | Quick web assessment |
| `portscan` | Port discovery |
| `cloud-enum` | Cloud storage/service discovery |
| `kitchen-sink` | Everything at once |

---

## Server Management

### Check Server Health

```bash
# If using HTTP transport
curl http://localhost:8080/health
```

### View Active Scans

```python
# List currently running scans
await list_scans()
```

### Stop a Scan

```python
# Cancel a running scan
await cancel_scan("scan_abc123")
```

---

## Troubleshooting

### Port Already in Use

```bash
# Find and kill existing process
lsof -i :8080 | grep LISTEN
kill -9 <PID>
```

### Module Not Recognized

Use `/list_modules` to see available modules, or check the manual.txt file.

### API Key Issues

Verify your key is set:
```bash
echo $OPENROUTER_API_KEY
# Should show your key
```

---

## Next Steps

- Read the [API Reference](API.md) for detailed tool documentation
- Review the [BBOT Manual](manual.txt) for available modules
- Check [CONTRIBUTING.md](CONTRIBUTING.md) to contribute