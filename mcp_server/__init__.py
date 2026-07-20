"""
BBOT MCP Server Package

This package provides a comprehensive MCP server implementation for
the BBOT security reconnaissance framework.
"""

from .scanner import BbotScanner
from .bbot_server import BbotMcpServer

__version__ = '1.0.0'
__all__ = [
    'BbotScanner',
    'BbotMcpServer'
]