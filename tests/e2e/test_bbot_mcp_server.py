#!/usr/bin/env python3
"""
End-to-End Tests for BBOT MCP Server

This test suite exercises all MCP tools via the actual FastMCP server
using pytest-asyncio and real subprocesses where appropriate.

Run with:
    python -m pytest tests/e2e/ -v
"""

import asyncio
import json
import os
import tempfile
import time
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch, MagicMock

# Import test fixtures and utilities
from tests.fixtures import *
from tests.utils import *


class TestMCPServer:
    """Core MCP Server Tests"""

    @pytest.fixture(autouse=True, scope="function")
    async def setup_server(self):
        """Set up server instance for each test"""
        from mcp_server.bbot_server import BbotMcpServer

        # Create fresh server instance
        self.server = BbotMcpServer()

        yield
        # Cleanup after each test
        try:
            for scan_id in list(self.server.scanner.active_scans.keys()):
                await self.server.cancel_scan(scan_id)
        except Exception:
            pass

        # Cleanup after each test
        # Stop any running scans
        for scan_id in list(self.server.scanner.active_scans.keys()):
            await self.server.cancel_scan(scan_id)

    @pytest.mark.asyncio
    async def test_server_initialization(self):
        """Test that server initializes correctly with default config"""
        assert self.server is not None
        assert self.server.mcp is not None
        assert self.server.scanner is not None
        assert self.server.config is not None

        # Verify default configuration exists
        assert 'scan' in self.server.config
        assert 'server' in self.server.config
        assert 'output' in self.server.config

    @pytest.mark.asyncio
    async def test_server_info(self):
        """Test server information endpoint"""
        info = self.server.get_server_info()

        assert info['name'] == 'BBOT Recon MCP Server'
        assert info['version'] == '1.0.0'
        assert 'active_scans' in info
        assert 'completed_scans' in info
        assert info['active_scans'] == 0
        assert info['completed_scans'] == 0


class TestStartScanTool:
    """Tests for start_scan MCP tool"""

    @pytest.fixture(autouse=True)
    async def setup(self):
        from mcp_server.bbot_server import BbotMcpServer
        self.server = BbotMcpServer()
        yield
        # Cleanup
        for scan_id in list(self.server.scanner.active_scans.keys()):
            await self.server.cancel_scan(scan_id)

    @pytest.mark.asyncio
    async def test_start_scan_valid_target(self):
        """Test starting scan with valid target"""
        result = await self.server.start_scan(targets=["example.com"])

        assert 'scan_id' in result
        assert result['status'] == 'in_progress'
        assert result['message'] == 'Scan started successfully'

        # Verify scan is tracked
        scan_id = result['scan_id']
        assert scan_id in self.server.scanner.active_scans

    @pytest.mark.asyncio
    async def test_start_scan_multiple_targets(self):
        """Test starting scan with multiple targets"""
        result = await self.server.start_scan(targets=["example.com", "test.com"])

        assert 'scan_id' in result
        scan_info = self.server.scanner.active_scans[result['scan_id']]
        assert scan_info['config']['targets'] == ["example.com", "test.com"]

    @pytest.mark.asyncio
    async def test_start_scan_with_presets(self):
        """Test starting scan with custom presets"""
        result = await self.server.start_scan(
            targets=["example.com"],
            presets=["subdomain-enum", "web-basic"]
        )

        assert 'scan_id' in result
        scan_info = self.server.scanner.active_scans[result['scan_id']]
        assert "subdomain-enum" in scan_info['config']['presets']
        assert "web-basic" in scan_info['config']['presets']

    @pytest.mark.asyncio
    async def test_start_scan_with_modules(self):
        """Test starting scan with custom modules"""
        result = await self.server.start_scan(
            targets=["example.com"],
            modules=["http", "portscan"]
        )

        assert 'scan_id' in result
        scan_info = self.server.scanner.active_scans[result['scan_id']]
        assert "http" in scan_info['config']['modules']
        assert "portscan" in scan_info['config']['modules']

    @pytest.mark.asyncio
    async def test_start_scan_with_custom_name(self):
        """Test starting scan with custom scan name"""
        result = await self.server.start_scan(
            targets=["example.com"],
            scan_name="my_custom_scan"
        )

        assert 'scan_id' in result
        scan_info = self.server.scanner.active_scans[result['scan_id']]
        assert scan_info['config']['scan_name'] == "my_custom_scan"

    @pytest.mark.asyncio
    async def test_start_scan_missing_target(self):
        """Test start_scan fails with missing target"""
        result = await self.server.start_scan(targets=[])

        assert 'error' in result
        assert result['error'] == 'Invalid configuration'
        assert 'Target is required' in result['details']

    @pytest.mark.asyncio
    async def test_start_scan_invalid_target(self):
        """Test start_scan fails with invalid target format"""
        result = await self.server.start_scan(targets=["invalid..target"])

        assert 'error' in result
        assert 'Invalid target format' in str(result['details'])

    @pytest.mark.asyncio
    async def test_start_scan_unknown_preset(self):
        """Test start_scan fails with unknown preset"""
        result = await self.server.start_scan(
            targets=["example.com"],
            presets=["nonexistent-preset"]
        )

        assert 'error' in result
        assert 'Unknown preset' in str(result['details'])

    @pytest.mark.asyncio
    async def test_start_scan_disallowed_module(self):
        """Test start_scan fails with disallowed module"""
        result = await self.server.start_scan(
            targets=["example.com"],
            modules=["malicious-module"]
        )

        assert 'error' in result
        assert 'Disallowed or unknown module' in str(result['details'])


class TestGetScanStatusTool:
    """Tests for get_scan_status MCP tool"""

    @pytest.fixture(autouse=True)
    async def setup(self):
        from mcp_server.bbot_server import BbotMcpServer
        self.server = BbotMcpServer()
        yield
        for scan_id in list(self.server.scanner.active_scans.keys()):
            await self.server.cancel_scan(scan_id)

    @pytest.mark.asyncio
    async def test_get_status_existing_scan(self):
        """Test getting status of active scan"""
        # Start a scan
        start_result = await self.server.start_scan(targets=["example.com"])
        scan_id = start_result['scan_id']

        # Get status
        status = await self.server.get_scan_status(scan_id)

        assert isinstance(status, str)
        assert "Status: in_progress" in status
        assert "example.com" in status or "Started:" in status

    @pytest.mark.asyncio
    async def test_get_status_nonexistent_scan(self):
        """Test getting status of nonexistent scan"""
        status = await self.server.get_scan_status("nonexistent_scan_123")

        assert "No active scan found" in status


class TestListFindingsTool:
    """Tests for list_findings MCP tool"""

    @pytest.fixture(autouse=True)
    async def setup(self):
        from mcp_server.bbot_server import BbotMcpServer
        self.server = BbotMcpServer()
        yield
        for scan_id in list(self.server.scanner.active_scans.keys()):
            await self.server.cancel_scan(scan_id)

    @pytest.mark.asyncio
    async def test_list_findings_active_scan(self):
        """Test listing findings from active scan returns empty (no results yet)"""
        start_result = await self.server.start_scan(targets=["example.com"])
        scan_id = start_result['scan_id']

        findings = await self.server.list_findings(scan_id, limit=10)

        assert isinstance(findings, dict)
        assert 'findings' in findings
        assert 'count' in findings
        assert findings['scan_id'] == scan_id
        assert findings['count'] == 0  # No findings yet for active scan

    @pytest.mark.asyncio
    async def test_list_findings_nonexistent_scan(self):
        """Test listing findings from nonexistent scan"""
        findings = await self.server.list_findings("nonexistent_scan")

        assert 'error' in findings


class TestListScansTool:
    """Tests for list_scans MCP tool"""

    @pytest.fixture(autouse=True)
    async def setup(self):
        from mcp_server.bbot_server import BbotMcpServer
        self.server = BbotMcpServer()
        yield
        for scan_id in list(self.server.scanner.active_scans.keys()):
            await self.server.cancel_scan(scan_id)

    @pytest.mark.asyncio
    async def test_list_scans_empty(self):
        """Test listing scans when none are active"""
        scans = await self.server.list_scans()

        assert isinstance(scans, list)
        assert len(scans) == 0

    @pytest.mark.asyncio
    async def test_list_scans_with_active(self):
        """Test listing scans with active scans"""
        # Start multiple scans
        await self.server.start_scan(targets=["example.com"])
        await self.server.start_scan(targets=["test.com"])

        scans = await self.server.list_scans()

        assert len(scans) == 2
        for scan in scans:
            assert 'scan_id' in scan
            assert 'status' in scan
            assert 'targets' in scan
            assert 'started' in scan


class TestGetScanDetailsTool:
    """Tests for get_scan_details MCP tool"""

    @pytest.fixture(autouse=True)
    async def setup(self):
        from mcp_server.bbot_server import BbotMcpServer
        self.server = BbotMcpServer()
        yield
        for scan_id in list(self.server.scanner.active_scans.keys()):
            await self.server.cancel_scan(scan_id)

    @pytest.mark.asyncio
    async def test_get_details_active_scan(self):
        """Test getting details of active scan"""
        start_result = await self.server.start_scan(
            targets=["example.com"],
            presets=["subdomain-enum"],
            scan_name="detail_test"
        )
        scan_id = start_result['scan_id']

        details = await self.server.get_scan_details(scan_id)

        assert details['scan_id'] == scan_id
        assert details['status'] == 'in_progress'
        assert details['targets'] == ["example.com"]
        assert "subdomain-enum" in details['presets']
        assert details['scan_name'] == "detail_test"
        assert 'start_time' in details
        assert 'duration_seconds' in details
        assert details['duration_seconds'] >= 0

    @pytest.mark.asyncio
    async def test_get_details_nonexistent_scan(self):
        """Test getting details of nonexistent scan"""
        details = await self.server.get_scan_details("nonexistent")

        assert 'error' in details
        assert 'not found' in details['error']


class TestCancelScanTool:
    """Tests for cancel_scan MCP tool"""

    @pytest.fixture(autouse=True)
    async def setup(self):
        from mcp_server.bbot_server import BbotMcpServer
        self.server = BbotMcpServer()
        yield

    @pytest.mark.asyncio
    async def test_cancel_active_scan(self):
        """Test cancelling an active scan"""
        start_result = await self.server.start_scan(targets=["example.com"])
        scan_id = start_result['scan_id']

        result = await self.server.cancel_scan(scan_id)

        assert result['status'] == 'cancelled'
        assert result['scan_id'] == scan_id
        assert scan_id not in self.server.scanner.active_scans
        assert scan_id in self.server.scanner.completed_scans

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_scan(self):
        """Test cancelling nonexistent scan"""
        result = await self.server.cancel_scan("nonexistent")

        assert 'error' in result
        assert 'not found' in result['error']


class TestDocsTool:
    """Tests for documentation generation tool"""

    @pytest.fixture(autouse=True)
    async def setup(self):
        from mcp_server.bbot_server import BbotMcpServer
        self.server = BbotMcpServer()
        yield

    @pytest.mark.asyncio
    async def test_docs_tool_exists(self):
        """Test that docs tool is registered"""
        # The docs tool should be available
        assert hasattr(self.server, 'get_api_docs')

        # Get the docs
        spec = await self.server.get_api_docs()

        assert isinstance(spec, dict)
        assert 'openapi' in spec
        assert spec['openapi'] == '3.0.0'
        assert 'info' in spec
        assert 'paths' in spec
        assert len(spec['paths']) > 0  # Should have tool endpoints

    @pytest.mark.asyncio
    async def test_openapi_spec_structure(self):
        """Test OpenAPI spec has correct structure"""
        spec = await self.server.get_api_docs()

        # Check required OpenAPI fields
        assert spec['openapi'] == '3.0.0'
        assert 'info' in spec
        assert spec['info']['title'] == 'BBOT Recon MCP Server API'
        assert 'paths' in spec

        # Check that all our tools have endpoints
        expected_endpoints = [
            'start-scan',
            'get-scan-status',
            'list-findings',
            'list-scans',
            'get-scan-details',
            'cancel-scan',
            'get-scan-output'
        ]

        for endpoint in expected_endpoints:
            path = f"/{endpoint}"
            assert path in spec['paths'], f"Missing endpoint: {path}"
            assert 'get' in spec['paths'][path]


class TestConfigValidation:
    """Tests for configuration validation"""

    @pytest.fixture(autouse=True)
    async def setup(self):
        from mcp_server.bbot_server import BbotMcpServer
        self.server = BbotMcpServer()
        yield

    def test_validate_scan_config_valid(self):
        """Test validation passes for valid config"""
        config = {
            'targets': ['example.com'],
            'presets': ['subdomain-enum'],
            'modules': ['http'],
            'scan_name': 'test_scan'
        }

        errors = self.server._validate_scan_config(config)
        assert errors == []

    def test_validate_scan_config_missing_target(self):
        """Test validation fails for missing target"""
        config = {'presets': ['subdomain-enum']}

        errors = self.server._validate_scan_config(config)
        assert 'Target is required' in errors

    def test_validate_scan_config_invalid_target(self):
        """Test validation fails for invalid target"""
        config = {'targets': ['invalid..domain']}

        errors = self.server._validate_scan_config(config)
        assert any('Invalid target format' in e for e in errors)

    def test_validate_scan_config_unknown_preset(self):
        """Test validation fails for unknown preset"""
        config = {
            'targets': ['example.com'],
            'presets': ['unknown-preset']
        }

        errors = self.server._validate_scan_config(config)
        assert any('Unknown preset' in e for e in errors)

    def test_validate_scan_config_invalid_module(self):
        """Test validation fails for disallowed module"""
        config = {
            'targets': ['example.com'],
            'modules': ['bad-module']
        }

        errors = self.server._validate_scan_config(config)
        assert any('Disallowed or unknown module' in e for e in errors)


class TestTargetValidation:
    """Tests for target validation"""

    @pytest.fixture(autouse=True)
    async def setup(self):
        from mcp_server.bbot_server import BbotMcpServer
        self.server = BbotMcpServer()
        yield

    def test_valid_domain(self):
        """Test valid domain names"""
        assert self.server._is_valid_target("example.com")
        assert self.server._is_valid_target("sub.example.com")
        assert self.server._is_valid_target("test.example.org")

    def test_valid_ip(self):
        """Test valid IP addresses"""
        assert self.server._is_valid_target("192.168.1.1")
        assert self.server._is_valid_target("10.0.0.1")

    def test_invalid_targets(self):
        """Test invalid targets"""
        assert not self.server._is_valid_target("")
        assert not self.server._is_valid_target("..")
        assert not self.server._is_valid_target(".example.com")
        assert not self.server._is_valid_target("example..com")
        assert not self.server._is_valid_target("not-a-valid-format")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])