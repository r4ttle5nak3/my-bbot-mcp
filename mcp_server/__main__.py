"""
Entry point for the BBOT MCP Server

This module provides the main initialization and execution logic
for the BBOT (Bighuge BLS OSINT Tool) MCP server.
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional

# ---------------------------------------------------------------------------
# Dependency check: verify the 'mcp' package is available before importing
# anything that depends on it. This gives a clear error message if the
# venv isn't activated.
# ---------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError as e:
    print("ERROR: Required package 'mcp' is not installed.", file=sys.stderr)
    print(file=sys.stderr)
    print("  This project uses a virtual environment. Activate it first:", file=sys.stderr)
    print(file=sys.stderr)
    print(f"    source {os.path.join(os.path.dirname(__file__), '..', 'venv', 'bin', 'activate')}", file=sys.stderr)
    print("    python -m mcp_server", file=sys.stderr)
    print(file=sys.stderr)
    print(f"  Or install the package directly:", file=sys.stderr)
    print("    pip install mcp", file=sys.stderr)
    print(file=sys.stderr)
    sys.exit(1)

from .scanner import BbotScanner
from .bbot_server import BbotMcpServer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global server instance
server = BbotMcpServer()


def main():
    """
    Main entry point for the BBOT MCP Server.
    """
    parser = argparse.ArgumentParser(
        description="BBOT MCP Server - Security reconnaissance via MCP"
    )
    parser.add_argument(
        '--transport', '-t',
        choices=['stdio', 'sse', 'streamable-http'],
        default='stdio',
        help="Transport protocol (default: stdio). Use 'streamable-http' for a persistent HTTP server."
    )
    parser.add_argument(
        '--host', '-H',
        default=None,
        help="Host address for SSE/HTTP transports (default: from config or 127.0.0.1)"
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=None,
        help="Port number for SSE/HTTP transports (default: from config or 8080)"
    )
    args = parser.parse_args()

    logger.info("Initializing BBOT MCP Server...")
    logger.info("Server configuration: %s", server.get_server_info())

    # Check that bbot is available on PATH
    bbot_path = server.scanner.bbot_path
    bbot_found = any(
        os.path.exists(os.path.join(p, bbot_path))
        for p in os.environ.get("PATH", "").split(os.pathsep)
    ) or os.path.exists(bbot_path)
    if not bbot_found:
        logger.warning("BBOT binary '%s' not found on PATH. Scans will fail.", bbot_path)
        logger.warning("Install BBOT: pip install bbot")

    # Report how many API keys are configured
    configured_keys = [k for k, v in server.config.get('api_keys', {}).items() if v]
    if configured_keys:
        logger.info("API keys configured: %d (%s)", len(configured_keys), ', '.join(configured_keys))
    else:
        logger.info("No API keys configured. Many BBOT modules will be unavailable.")

    try:
        server.run(transport=args.transport, host=args.host, port=args.port)
    except Exception as e:
        logger.error("Server failed to start: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()