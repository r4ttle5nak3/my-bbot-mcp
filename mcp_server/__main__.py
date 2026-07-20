"""
Entry point for the BBOT MCP Server

This module provides the main initialization and execution logic
for the BBOT (Bighuge BLS OSINT Tool) MCP server.
"""

import sys
import os
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from mcp.server.fastmcp import FastMCP

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
    logger.info("Initializing BBOT MCP Server...")
    logger.info("Server configuration: %s", server.get_server_info())

    try:
        server.run(transport="stdio")
    except Exception as e:
        logger.error("Server failed to start: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()