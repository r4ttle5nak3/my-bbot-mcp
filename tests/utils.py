#!/usr/bin/env python3
"""
Test Utilities for BBOT MCP Server

Utility helpers for constructing test data, mocking subprocesses,
and performing common test operations.
"""

import sys
import unittest
import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

import pytest


class AssertionMixin:
    """Mixin class for additional assertion methods"""

    def assertInList(self, item, lst, msg=None):
        """Assert that item is in the list"""
        msg = msg or f"{item} not found in list"
        if item not in lst:
            raise AssertionError(msg)

    def assertListEqual(self, first, second, msg=None):
        """Assert that two lists are equal"""
        msg = msg or "Lists are not equal"
        if list(first) != list(second):
            raise AssertionError(msg)

    def assertAllEqual(self, first, second, msg=None):
        """Assert that all elements are equal pair-wise"""
        msg = msg or "Not all elements are equal"
        for f, s in zip(first, second):
            if f != s:
                raise AssertionError(f"{f} != {s}")
        if len(first) != len(second):
            raise AssertionError("Lists are of different lengths")


class IssueTracker:
    """Simple issue tracking for tests"""

    def __init__(self, name="BBOT test issue"):
        self.name = name
        self.skipped = False
        self.description = ""

    def skip(self, reason="No reason provided"):
        self.skipped = True
        self.description = reason

    def assert_skip(self):
        if self.skipped:
            raise unittest.SkipTest(self.description)


# Global test data builder
class TestDataBuilder:
    """Builder for test data structures"""

    @staticmethod
    def scan_config(**kwargs) -> Dict[str, Any]:
        """Build a default scan configuration"""
        defaults = {
            'targets': ['example.com'],
            'presets': ['subdomain-enum'],
            'modules': ['http'],
            'scan_name': 'test_scan',
            'timeout': 300
        }
        defaults.update(kwargs)
        return defaults

    @staticmethod
    def findings(count: int = 5) -> List[str]:
        """Build a list of findings"""
        return [f"[DNS_NAME] subdomain{i}.example.com" for i in range(count)]

    @staticmethod
    def scan_details(
        scan_id: str = None,
        status: str = 'in_progress',
        targets: List[str] = None,
        presets: List[str] = None,
        modules: List[str] = None
    ) -> Dict[str, Any]:
        """Build a scan details dictionary"""
        return {
            'scan_id': scan_id or f"scan_{TestDataBuilder.uuid4()}",
            'status': status,
            'targets': targets or ['example.com'],
            'presets': presets or ['subdomain-enum'],
            'modules': modules or ['http']
        }

    @staticmethod
    def uuid4():
        """Generate a simple UUID-like string"""
        import uuid
        return str(uuid.uuid4())[:8]


# Basic assertion helpers
def assert_contains(s: str, substr: str, msg=None):
    """Assert that string contains substring"""
    msg = msg or f"String '{s}' does not contain '{substr}'"
    assert substr in s, msg


def assert_dict_contains(d: dict, keys: List[str], msg=None):
    """Assert that dict contains specific keys"""
    msg = msg or f"Dict does not contain all specified keys: {keys}"
    for key in keys:
        assert key in d, f"{key} not in dict keys {list(d.keys())}, {msg}"


def assert_keys_equal(d: dict, expected_keys: List[str], msg=None):
    """Assert that dict has exactly the expected keys"""
    keys = list(d.keys())
    if set(keys) != set(expected_keys):
        raise AssertionError(f"Expected keys {expected_keys}, got {keys}")


# Mock implementation for subprocess
class MockSubprocessProcess:
    """Mock subprocess process object"""

    def __init__(self, stdout='', stderr='', return_code=0, simulate_delay=0.1):
        self.pid = 12345
        self._stdout_data = stdout
        self._stderr_data = stderr
        self._return_code = return_code
        self._simulate_delay = simulate_delay
        self._terminated = False
        self.stdout = type('MockStream', (), {'readline': lambda self: self._get_line()})()
        self.stderr = type('MockStream', (), {'readline': lambda self: self._get_line()})()
        self.closed = False

    def _get_line(self):
        if hasattr(self, '_lines'):
            if self._line_index < len(self._lines):
                line = self._lines[self._line_index]
                self._line_index += 1
                return line
        return None

    def read(self, size=-1):
        return self._stdout_data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


# Command wrappers for tests
def mock_execute_command(cmd_list: List[str], timeout: int = 5, simulate_delay: float = 0.1):
    """Mock command execution"""
    return subprocess_factory(cmd_list, simulate_delay)


def subprocess_factory(cmd_list: List[str], simulate_delay: float = 0.1):
    """Create a mock subprocess object"""
    mock_process = subprocess_factory_helper()
    mock_process.stdout_data = simulate_file_data(cmd_list[1] if len(cmd_list) > 1 else '')
    mock_process.stderr_data = simulate_file_data()
    return mock_process


def simulate_file_data(content=''):
    """Wrap content in a readable mock file object"""
    mock = type('MockFile', (), {})()
    mock.read = lambda: content
    return mock


# Test state management
_test_state = {
    'saves': [],
    'loads': [],
    'removes': set()
}


def set_test_save(obj, filename):
    """Track file save operations for test rollback"""
    _test_state['saves'].append((obj, filename))
    # Actually save
    import os
    dir_name = os.path.dirname(filename) if os.path.dirname(filename) else '.'
    os.makedirs(dir_name, exist_ok=True)
    with open(filename, 'wb') as f:
        pass


def rollback_test_saves():
    """Rollback file operations during tests"""
    for obj, filename in _test_state.get('saves', []):
        # In real test, we might not actually save
        pass


def reset_test_state():
    """Reset test state between test cases"""
    _test_state.clear()


# Process utilities
def subprocess_factory_helper():
    """Create a mock subprocess process"""
    class MockProcess:
        def __init__(self):
            self.pid = 12345
            self._terminated = False

        def poll(self):
            return None if not self._terminated else 0

        def terminate(self):
            self._terminated = True

        def kill(self):
            self._terminated = True

        def communicate(self, timeout=None):
            return ('stdout\n', 'stderr\n')

        def stdout(self):
            class MockStream:
                def readline(self):
                    return ''
    return MockProcess()


# Process control helpers
def simulate_process_terminate(process, delay=0.1):
    """Simulate process termination"""
    import time
    time.sleep(delay)
    process.terminate()


# Command wrappers
def mock_execute_cmd(cmd_list, simulate_delay=0.1):
    """Mock command execution with async support"""
    mock_process = subprocess_factory()
    mock_process.stdout_data = 'mock stdout\n'
    mock_process.stderr_data = 'mock stderr\n'
    asyncio.create_task(simulate_process_terminate(mock_process, simulate_delay))
    return mock_process


def async_execute_mock(return_result=None, delay=0.1):
    """Mock async command execution"""
    async def mock_func():
        import asyncio
        await asyncio.sleep(delay)
        return return_result
    return mock_func


# Data generators
def generate_test_findings(count=5, prefix="finding"):
    """Generate test findings"""
    return [f"{prefix} {i} - sample issue content" for i in range(count)]


def generate_test_modules(modules=None):
    """Generate test module config"""
    default_modules = ['module_one', 'module_two', 'module_three']
    return modules or default_modules[:len(modules)]


# Test configuration
class TestConfigBuilder:
    """Build test configuration objects"""

    def __init__(self, base_config=None):
        self.config = base_config or {}

    def add_section(self, section_name, config_dict):
        """Add a new configuration section"""
        if section_name not in self.config:
            self.config[section_name] = {}
        self.config[section_name].update(config_dict)
        return self

    def get(self):
        """Return the complete config"""
        return self.config.copy()


# File operation helpers
def save_mock_file(path: Path, content: str = 'mock content'):
    """Save mock file content"""
    with open(path, 'w') as f:
        f.write(content)


def delete_mock_file(path: Path):
    """Delete mock file"""
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def backup_and_restore(path: Path, backup_data=None):
    """Backup and restore file content"""
    if not path.exists():
        return
    backup_data = getattr(backup_and_restore, 'backup_data', None)
    if backup_data:
        path.write_text(backup_data)
        setattr(backup_and_restore, 'backup_data', None)
    else:
        backup_and_restore.backup_data = path.read_text()


# Error handling helpers
class TestException(Exception):
    """Base exception for test cases"""
    pass


class SkipTestException(Exception):
    """Exception for skipping test cases"""
    def __init__(self, message):
        super().__init__(message)
        self.message = message


# Test lifecycle management
@pytest.fixture(autouse=True)
def test_setup_teardown():
    """Automatic test setup and teardown"""
    # Setup - called before each test
    yield
    # Teardown - called after each test
    reset_test_state()


class TestTracker:
    """Global test tracking for reporting"""

    failures = []
    successes = []
    skips = []
    errors = []

    @staticmethod
    def record_result(result_type: str, test_name: str, error_msg=None):
        """Record test result"""
        record = {
            'type': result_type,
            'name': test_name,
            'error': error_msg
        }
        if result_type == 'failure':
            TestTracker.failures.append(record)
        elif result_type == 'success':
            TestTracker.successes.append(record)
        elif result_type == 'skip':
            TestTracker.skips.append(record)
        elif result_type == 'error':
            TestTracker.errors.append(record)


# Performance metrics
def measure_execution_time(func):
    """Decorator for measuring function execution time"""
    import time
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        elapsed = end - start
        # Store duration somewhere for reporting
        if not hasattr(wrapper, 'elapsed'):
            wrapper.elapsed = 0
        wrapper.elapsed = elapsed
        return result
    return wrapper


# Context manager for temporary directory
class temporary_directory:
    """Context manager for creating and cleaning up temp directories"""

    def __init__(self, suffix=''):
        self.suffix = suffix
        self.dir = None

    def __enter__(self):
        import tempfile
        self.dir = tempfile.mkdtemp(suffix=self.suffix)
        return self.dir

    def __exit__(self, exc_type, exc_val, exc_tb):
        import os
        if self.dir and os.path.exists(self.dir):
            for file in os.listdir(self.dir):
                os.unlink(os.path.join(self.dir, file))
            os.rmdir(self.dir)


# Time-aware testing
def watch_for_timeout(timeout_seconds=30, test_func=None):
    """Run test function with timeout protection"""
    import asyncio
    import threading

    result = {}

    def run_test():
        try:
            result['result'] = test_func()
            result['status'] = 'completed'
        except Exception as e:
            result['exception'] = e
            result['status'] = 'failed'

    thread = threading.Thread(target=run_test)
    thread.start()
    thread.join()
    return result


# Async timeout handling
async def async_timeout_sleep(seconds):
    """Async sleep with timeout consideration"""
    import asyncio
    await asyncio.sleep(seconds)


# End of utilities