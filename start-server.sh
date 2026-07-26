#!/usr/bin/env bash
# =============================================================================
# BBOT MCP Server Launcher
# =============================================================================
# Starts the BBOT MCP server in streamable-http (persistent) mode.
# State persists across MCP tool calls — scans stay alive, status checks work.
#
# Usage:
#   ./start-server.sh                    # Default: port 8080
#   ./start-server.sh --port 9090        # Custom port
#   ./start-server.sh --host 0.0.0.0     # Listen on all interfaces
#
# Claude Code connects via .mcp.json (bbot-recon-http entry).
# Press Ctrl+C to stop the server.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="${SCRIPT_DIR}/venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "ERROR: Virtual environment not found at ${SCRIPT_DIR}/venv"
    echo "Create it: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

echo "============================================"
echo "  BBOT MCP Server (streamable-http mode)"
echo "============================================"
echo ""
echo "  URL: http://127.0.0.1:8080/mcp"
echo "  (configured in .mcp.json as bbot-recon-http)"
echo ""
echo "  Press Ctrl+C to stop"
echo "============================================"
echo ""

exec "$VENV_PYTHON" -m mcp_server --transport streamable-http "$@"