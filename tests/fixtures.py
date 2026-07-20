#!/usr/bin/env python3
"""
Test Fixtures for BBOT MCP Server Tests

This module provides pytest fixtures for setting up test environments,
mocking subprocesses, and creating test data.
"""

import asyncio
import json
import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from typing import Dict, Any, List


@pytest.fixture
def mock_subprocess():
    """Mock subprocess.Popen for testing without real BBOT execution"""
    with patch('subprocess.Popen') as mock_popen:
        # Create a mock process
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None  # Process is running
        mock_process.stdout.readline = Mock(return_value='')
        mock_process.stderr.readline = Mock(return_value='')
        mock_process.terminate = Mock()
        mock_process.kill = Mock()
        mock_process.communicate = Mock(return_value=('output', 'error'))

        mock_popen.return_value = mock_process
        yield mock_process


@pytest.fixture
def temp_output_dir():
    """Create a temporary directory for scan outputs"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_scan_config():
    """Sample valid scan configuration for testing"""
    return {
        'targets': ['example.com'],
        'presets': ['subdomain-enum'],
        'modules': ['http', 'portscan'],
        'scan_name': 'test_scan',
        'timeout': 300
    }


@pytest.fixture
def sample_scan_configs():
    """Multiple sample scan configurations"""
    return [
        {
            'targets': ['example.com'],
            'presets': ['subdomain-enum'],
            'modules': ['http']
        },
        {
            'targets': ['test.com', 'demo.com'],
            'presets': ['web-basic'],
            'modules': ['http', 'portscan', 'gowitness']
        },
        {
            'targets': ['192.168.1.1'],
            'presets': ['portscan'],
            'modules': ['portscan', 'nuclei']
        }
    ]


@pytest.fixture
def sample_findings():
    """Sample findings data for testing"""
    return [
        "[DNS_NAME] example.com",
        "[DNS_NAME] www.example.com",
        "[IP_ADDRESS] 192.168.1.1",
        "[HTTP_RESPONSE] 200 OK at https://example.com",
        "[OPEN_TCP_PORT] Port 80 is open",
        "[VULNERABILITY] CVE-2023-1234 detected"
    ]


@pytest.fixture
def mock_bbot_output():
    """Mock BBOT scan output"""
    return {
        'events': [
            {'type': 'DNS_NAME', 'data': 'example.com'},
            {'type': 'DNS_NAME', 'data': 'www.example.com'},
            {'type': 'OPEN_TCP_PORT', 'data': 'Port 80 open'},
            {'type': 'HTTP_RESPONSE', 'data': '200 OK'}
        ]
    }


@pytest.fixture
def sample_openapi_spec():
    """Sample OpenAPI spec for testing"""
    return {
        'openapi': '3.0.0',
        'info': {
            'title': 'BBOT Recon MCP Server API',
            'description': 'Security reconnaissance and OSINT analysis using BBOT.',
            'version': '1.0.0'
        },
        'paths': {
            '/start-scan': {
                'get': {
                    'summary': 'Start Scan',
                    'description': 'Execute a new BBOT reconnaissance scan.',
                    'parameters': [],
                    'responses': {
                        '200': {'description': 'Successful response'}
                    }
                }
            }
        }
    }


@pytest.fixture
def event_loop():
    """Create an event loop for async tests"""
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def bbot_server_instance():
    """Create a BBOT server instance for testing"""
    from mcp_server.bbot_server import BbotMcpServer
    server = BbotMcpServer()
    yield server

    # Cleanup: cancel any running scans
    async def cleanup():
        for scan_id in list(server.scanner.active_scans.keys()):
            await server.cancel_scan(scan_id)

    asyncio.get_event_loop().run_until_complete(cleanup())


@pytest.fixture
def mock_async_scan():
    """Mock async scan execution for testing"""
    async def execute_mock(scan_config):
        scan_id = f"scan_{hash(str(scan_config)) % 10000}"
        return {
            'scan_id': scan_id,
            'status': 'in_progress',
            'message': 'Mock scan started'
        }
    return execute_mock


@pytest.fixture
def test_config():
    """Test configuration overrides"""
    return {
        'scan': {
            'default_timeout': 10,
            'default_presets': ['subdomain-enum'],
            'allowed_modules': [
                'subdomain-enum', 'web-basic', 'web-thorough',
                'portscan', 'http', 'pinpoint', 'cloud-enum',
                'technology', 'vulnerability', 'export'
            ],
            'max_concurrent_scans': 2
        },
        'server': {
            'host': 'localhost',
            'port': 8080,
            'log_level': 'DEBUG'
        },
        'output': {
            'directory': 'test_outputs',
            'formats': ['json', 'text'],
            'max_file_size': 1024 * 1024
        }
    }


class MockProcess:
    """Mock subprocess process for testing"""

    def __init__(self, stdout_data='', stderr_data='', return_code=0, simulate_delay=0.5):
        self.pid = 12345
        self._stdout_data = stdout_data
        self._stderr_data = stderr_data
        self._return_code = return_code
        self._simulate_delay = simulate_delay
        self._terminated = False

    def poll(self):
        if self._terminated:
            return self._return_code
        return None  # Still running

    def terminate(self):
        self._terminated = True

    def kill(self):
        self._terminated = True
        self._return_code = -1

    def communicate(self, timeout=None):
        import time
        if self._simulate_delay > 0:
            time.sleep(self._simulate_delay)
        return (self._stdout_data, self._stderr_data)

    def wait(self, timeout=None):
        if self._simulate_delay > 0:
            import time
            time.sleep(self._simulate_delay)
        return self._return_code


@pytest.fixture
def mock_process_factory():
    """Factory for creating mock processes with specific behavior"""
    def create_process(stdout='', stderr='', return_code=0, delay=0.1):
        return MockProcess(stdout, stderr, return_code, delay)
    return create_process


class TestDataBuilder:
    """Builder class for creating test data"""

    @staticmethod
    def build_scan_result(
        scan_id: str = 'scan_test',
        status: str = 'in_progress',
        targets: List[str] = None,
        presets: List[str] = None,
        modules: List[str] = None,
        duration: float = 0.0
    ) -> Dict[str, Any]:
        """Build a scan result dictionary"""
        return {
            'scan_id': scan_id,
            'status': status,
            'targets': targets or ['example.com'],
            'presets': presets or ['subdomain-enum'],
            'modules': modules or ['http'],
            'duration_seconds': duration
        }

    @staticmethod
    def build_findings(count: int = 5) -> List[str]:
        """Build sample findings list"""
        findings = []
        for i in range(count):
            findings.append(f"[DNS_NAME] subdomain{i}.example.com")
        return findings

    @staticmethod
    def build_openapi_spec(num_endpoints: int = 3) -> Dict[str, Any]:
        """Build a minimal OpenAPI spec"""
        paths = {}
        tools = ['start-scan', 'get-scan-status', 'list-findings']

        for i, tool in enumerate(tools[:num_endpoints]):
            paths[f'/{tool}'] = {
                'get': {
                    'summary': f'{tool.replace("-", " ").title()} Tool',
                    'description': f'Execute {tool} operation',
                    'parameters': [],
                    'responses': {
                        '200': {
                            'description': 'Successful response',
                            'content': {
                                'application/json': {
                                    'schema': {'type': 'object'}
                                }
                            }
                        }
                    }
                }
            }

        return {
            'openapi': '3.0.0',
            'info': {
                'title': 'BBOT Recon MCP Server API',
                'version': '1.0.0'
            },
            'paths': paths
        }


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )


def pytest_unconfigure(config):
    """Cleanup after pytest session"""
    # Clean up any temporary files or directories
    pass