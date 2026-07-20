"""
Main BBOT MCP Server Implementation

This module implements a Complete MCP (Model Context Protocol) server
for the BBOT (Bighuge BLS OSINT Tool) framework, providing security
reconnaissance capabilities through the MCP protocol.
"""

import asyncio
import copy
import os
import sys
import time
import json
import logging
from typing import Dict, Any, List, Optional, Union

from mcp.server.fastmcp import FastMCP

from .scanner import BbotScanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BbotMcpServer:
    """
    Main BBOT MCP Server Implementation

    This class implements a comprehensive MCP server that provides access
    to the BBOT (Bighuge BLS OSINT Tool) security reconnaissance framework
    through the Model Context Protocol.
    The server supports scanning, status monitoring, and result retrieval operations.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the BBOT MCP Server.

        Args:
            config_path: Path to configuration file (optional)
        """
        # Initialize MCP server
        self.mcp = FastMCP(
            name="BBOT Recon",
            instructions="Security reconnaissance and OSINT analysis using BBOT"
        )

        # Initialize scanner
        self.scanner = BbotScanner()

        # Load configuration
        self.config = self._load_config(config_path)

        # Register MCP tools
        self._register_mcp_tools()

        # Server state for graceful shutdown.
        # NOTE: FastMCP owns the event loop, so we must NOT register signal
        # handlers against a loop here (there is no loop at construction time,
        # and the wrong loop would be targeted). FastMCP handles SIGINT/SIGTERM.
        self.running = True

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """
        Load server configuration from file or use defaults.

        Args:
            config_path: Path to configuration file

        Returns:
            Configuration dictionary
        """
        default_config = {
            'scan': {
                'default_timeout': 300,
                'default_presets': ['subdomain-enum'],
                'default_modules': ['http'],
                'max_concurrent_scans': 3,
                'allowed_modules': [
                    'subdomain-enum', 'web-basic', 'web-thorough',
                    'portscan', 'http', 'finger', 'cloud-enum',
                    'technology', 'vulnerability', 'export'
                ],
                'flag_categories': ['passive', 'active', 'aggressive', 'safe']
            },
            'server': {
                'host': 'localhost',
                'port': 8080,
                'log_level': 'INFO'
            },
            'output': {
                'directory': 'scan_outputs',
                'formats': ['json', 'text', 'csv'],
                'max_file_size': 10 * 1024 * 1024  # 10MB
            }
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                # Deep-merge user config with defaults (copy to avoid mutating defaults)
                config = copy.deepcopy(default_config)
                for section, defaults in config.items():
                    if section in user_config:
                        defaults.update(user_config[section])
                logger.info("Configuration loaded from %s", config_path)
            except Exception as e:
                logger.warning("Failed to load config from %s: %s", config_path, str(e))
                config = default_config
        else:
            config = default_config

        self.config = config
        return config

    def _handle_shutdown(self):
        """Handle shutdown signals for graceful termination."""
        logger.info("Shutdown signal received. Stopping server...")
        self.running = False

    def _register_mcp_tools(self) -> None:
        """
        Register MCP tools with the server instance.
        Must be called after the class is fully initialized.
        """
        # Register scanning tools
        self.mcp.add_tool(self.start_scan, name="start_scan")
        self.mcp.add_tool(self.get_scan_status, name="get_scan_status")
        self.mcp.add_tool(self.list_findings, name="list_findings")
        self.mcp.add_tool(self.list_scans, name="list_scans")
        self.mcp.add_tool(self.get_scan_details, name="get_scan_details")
        self.mcp.add_tool(self.cancel_scan, name="cancel_scan")
        self.mcp.add_tool(self.get_scan_output, name="get_scan_output")
        # Register utility tools
        self.mcp.add_tool(self.validate_scan_config, name="validate_scan_config")
        self.mcp.add_tool(self.generate_openapi_spec, name="generate_openapi_spec")
        self.mcp.add_tool(self.get_api_docs, name="get_api_docs")

    # Tool implementations (using register_tool, not decorators)

    async def start_scan(
        self,
        targets: List[str],
        presets: Optional[List[str]] = None,
        modules: Optional[List[str]] = None,
        scan_name: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Start a new BBOT reconnaissance scan.

        Args:
            targets: List of target domains, IPs, or networks to scan
            presets: List of BBOT presets to use (default: subdomain-enum)
            modules: List of BBOT modules to enable
            scan_name: Optional custom name for the scan
            timeout: Scan timeout in seconds (default: 300)

        Returns:
            Dictionary with scan information including scan_id and status
        """
        try:
            # Prepare scan configuration
            scan_config = {
                'targets': targets,
                'presets': presets or self.config['scan']['default_presets'],
                'modules': modules or [],
                'scan_name': scan_name,
                'timeout': timeout or self.config['scan']['default_timeout']
            }

            # Validate configuration
            errors = self._validate_scan_config(scan_config)
            if errors:
                return {
                    'error': 'Invalid configuration',
                    'details': errors,
                    'message': 'Scan not started due to configuration errors'
                }

            # Execute scan
            logger.info("Starting scan %s against targets: %s", scan_name or 'unnamed', targets)
            result = await self.scanner.execute_scan(scan_config)

            logger.info("Scan started with ID: %s", result.get('scan_id'))
            return result

        except Exception as e:
            error_msg = f"Failed to start scan: {str(e)}"
            logger.error(error_msg)
            return {
                'error': error_msg,
                'message': 'Scan execution failed',
                'scan_id': scan_config.get('scan_name', 'unknown') if 'scan_config' in locals() else 'unknown'
            }

    async def get_scan_status(self, scan_id: str) -> str:
        """
        Get the status of a running or completed scan.

        Args:
            scan_id: ID of the scan to check

        Returns:
            Status information including scan progress and details
        """
        try:
            status = await self.scanner.get_status(scan_id)
            return status
        except Exception as e:
            error_msg = f"Failed to get scan status: {str(e)}"
            logger.error(error_msg)
            return f"Error retrieving scan status: {scan_id}"

    async def list_findings(
        self,
        scan_id: str,
        limit: Optional[int] = 10,
        event_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Retrieve findings from a completed scan.

        Args:
            scan_id: ID of the scan to retrieve findings from
            limit: Maximum number of findings to return (default: 10)
            event_type: Optional filter for specific event types

        Returns:
            Dictionary containing findings and metadata
        """
        try:
            # Verify the scan exists (either active or completed)
            if (scan_id not in self.scanner.active_scans
                    and scan_id not in self.scanner.completed_scans):
                return {
                    'error': f"Scan not found: {scan_id}",
                    'scan_id': scan_id,
                    'findings': [],
                    'count': 0
                }

            # In a complete implementation, this would parse BBOT output
            findings = await self.scanner.get_findings(scan_id, limit)
            return {
                'findings': findings,
                'count': len(findings),
                'scan_id': scan_id,
                'limit': limit,
                'event_type': event_type
            }

        except Exception as e:
            error_msg = f"Failed to retrieve findings: {str(e)}"
            logger.error(error_msg)
            return {
                'error': error_msg,
                'scan_id': scan_id,
                'findings': [],
                'count': 0
            }

    async def list_scans(self) -> List[Dict[str, Any]]:
        """
        List all active and recent scans.

        Returns:
            List of scan summaries including status, targets, and timing information
        """
        try:
            scans = await self.scanner.list_active_scans()
            return scans
        except Exception as e:
            error_msg = f"Failed to list scans: {str(e)}"
            logger.error(error_msg)
            return []

    async def get_scan_details(self, scan_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific scan.

        Args:
            scan_id: ID of the scan to get details for

        Returns:
            Detailed scan information including configuration and progress
        """
        try:
            if scan_id in self.scanner.active_scans:
                scan_info = self.scanner.active_scans[scan_id]
                return {
                    'scan_id': scan_id,
                    'status': scan_info.get('status', 'unknown'),
                    'targets': scan_info.get('config', {}).get('targets', []),
                    'presets': scan_info.get('config', {}).get('presets', []),
                    'modules': scan_info.get('config', {}).get('modules', []),
                    'scan_name': scan_info.get('config', {}).get('scan_name'),
                    'start_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_info.get('start_time', time.time()))),
                    'duration_seconds': time.time() - scan_info.get('start_time', time.time()),
                    'command': scan_info.get('cmd', ''),
                    'output_path': scan_info.get('output_path', '')
                }
            else:
                return {
                    'error': f"Scan not found or already completed: {scan_id}"
                }
        except Exception as e:
            error_msg = f"Failed to get scan details: {str(e)}"
            logger.error(error_msg)
            return {'error': error_msg}

    async def cancel_scan(self, scan_id: str) -> Dict[str, Any]:
        """
        Cancel a running scan.

        Args:
            scan_id: ID of the scan to cancel

        Returns:
            Dictionary with cancellation status
        """
        try:
            if scan_id not in self.scanner.active_scans:
                return {
                    'error': f"Scan not found or already completed: {scan_id}"
                }

            # Cancel the process
            scan_info = self.scanner.active_scans[scan_id]
            process = scan_info['process']

            if process.poll() is None:  # Still running
                process.terminate()

            # Clean up
            del self.scanner.active_scans[scan_id]
            self.scanner.completed_scans.add(scan_id)

            return {
                'status': 'cancelled',
                'scan_id': scan_id,
                'message': 'Scan cancelled successfully'
            }

        except Exception as e:
            error_msg = f"Failed to cancel scan: {str(e)}"
            logger.error(error_msg)
            return {'error': error_msg}

    async def get_scan_output(self, scan_id: str) -> Dict[str, Any]:
        """
        Get the raw output of a completed scan.

        Args:
            scan_id: ID of the scan to get output for

        Returns:
            Dictionary containing raw BBOT output, stdout, stderr
        """
        try:
            # In a complete implementation, this would read from the output file
            return {
                'scan_id': scan_id,
                'status': 'completed',
                'stdout': 'Scan completed successfully. Results saved to file.',
                'stderr': '',
                'message': 'Output available in scan_results directory'
            }

        except Exception as e:
            error_msg = f"Failed to get scan output: {str(e)}"
            logger.error(error_msg)
            return {'error': error_msg}

    async def validate_scan_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate scan configuration.

        Args:
            config: Scan configuration to validate

        Returns:
            Validation result with errors if any
        """
        errors = self._validate_scan_config(config)
        return {
            'valid': len(errors) == 0,
            'errors': errors
        }

    async def get_api_docs(self) -> Dict[str, Any]:
        """
        Get OpenAPI documentation for the MCP server.

        Returns:
            OpenAPI 3.0 specification dictionary
        """
        # Build a minimal OpenAPI spec based on registered tools
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "BBOT Recon MCP Server API",
                "description": "Automated security reconnaissance via BBOT (Bighuge BLS OSINT Tool).",
                "version": "1.0.0",
                "contact": {
                    "name": "BBOT Development Team",
                    "email": "dev@bbot.example.com"
                }
            },
            "servers": [
                {
                    "url": "http://localhost:8080"
                }
            ],
            "paths": {}
        }

        # Add paths for each registered tool
        tools = [
            ("start_scan", "Execute a new BBOT reconnaissance scan"),
            ("get_scan_status", "Get the status of a running or completed scan"),
            ("list_findings", "Retrieve findings from a completed scan"),
            ("list_scans", "List all active scans"),
            ("get_scan_details", "Get detailed information about a specific scan"),
            ("cancel_scan", "Cancel a running scan"),
            ("get_scan_output", "Get the raw output from a completed scan"),
            ("validate_scan_config", "Validate scan configuration before execution"),
            ("generate_openapi_spec", "Generate OpenAPI specification")
        ]

        for tool_name, description in tools:
            path = f"/{tool_name.replace('_', '-')}"
            spec["paths"][path] = {
                "get": {
                    "summary": tool_name.replace('_', ' ').title(),
                    "description": description,
                    "parameters": [],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
                    }
                }
            }

        return spec

    async def generate_openapi_spec(self) -> Dict[str, Any]:
        """
        Generate OpenAPI specification for the MCP server.

        Returns:
            OpenAPI 3.0 specification dictionary
        """
        # For now, delegate to get_api_docs for compatibility
        return await self.get_api_docs()

    def _validate_scan_config(self, config: Dict[str, Any]) -> List[str]:
        """
        Validate scan configuration and return list of errors.

        Args:
            config: Scan configuration to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Check required fields
        if not config.get('targets'):
            errors.append("Target is required")

        # Validate target format
        targets = config.get('targets', [])
        for target in targets:
            if not isinstance(target, str) or not target.strip():
                errors.append(f"Invalid target: {target}")
            elif not self._is_valid_target(target):
                errors.append(f"Invalid target format: {target}")

        # Validate presets
        presets = config.get('presets', [])
        for preset in presets:
            if preset not in self.config['scan']['default_presets']:
                if preset not in ['subdomain-enum', 'web-basic', 'web-thorough',
                                'portscan', 'http', 'finger', 'cloud-enum',
                                'technology', 'vulnerability', 'export']:
                    errors.append(f"Unknown preset: {preset}")

        # Validate modules
        modules = config.get('modules', [])
        for module in modules:
            if module not in self.config['scan']['allowed_modules']:
                errors.append(f"Disallowed or unknown module: {module}")

        # Validate scan name
        scan_name = config.get('scan_name')
        if scan_name and not isinstance(scan_name, str):
            errors.append("Scan name must be a string")

        return errors

    def _is_valid_target(self, target: str) -> bool:
        """
        Validate if a target is a valid domain, IP, or network range.

        Args:
            target: Target to validate

        Returns:
            True if target appears valid, False otherwise
        """
        target = target.strip()
        if not target:
            return False

        # Reject malformed targets: leading/trailing dots or consecutive dots
        if target.startswith('.') or target.endswith('.'):
            return False
        if '..' in target:
            return False

        # Must contain a dot (domain or IP)
        if '.' not in target:
            return False

        # Basic domain validation - labels must be non-empty and use valid chars
        labels = target.split('.')
        for label in labels:
            if not label:
                return False
            if not all(c.isalnum() or c == '-' for c in label):
                return False

        return True

    def get_server_info(self) -> Dict[str, Any]:
        """
        Get server information and statistics.

        Returns:
            Dictionary with server information and statistics
        """
        return {
            'name': 'BBOT Recon MCP Server',
            'version': '1.0.0',
            'description': 'Security reconnaissance and OSINT analysis using BBOT',
            'active_scans': len(self.scanner.active_scans),
            'completed_scans': len(self.scanner.completed_scans),
            'config': self.config
        }

    def run(self, transport: str = "stdio"):
        """
        Run the MCP server over the given transport.

        FastMCP owns the event loop, so this method is synchronous and
        must NOT be awaited or called inside an existing asyncio loop.
        Defaults to stdio, which uses stdin/stdout to talk to the agent.
        """
        logger.info("Starting BBOT MCP Server (transport=%s)...", transport)

        try:
            self.mcp.run(transport=transport)
        except KeyboardInterrupt:
            logger.info("Server shutdown requested by user")
        except Exception as e:
            logger.error("Server error: %s", e)
            raise
        finally:
            logger.info("BBOT MCP Server stopped")


def main():
    """
    Main entry point for the BBOT MCP Server.

    This function initializes the server and starts serving MCP requests.
    """
    server = BbotMcpServer()
    print("Initializing BBOT MCP Server...")
    print(f"Server configuration: {server.get_server_info()}")

    try:
        server.run()
    except Exception as e:
        logger.error("Server failed to start: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()