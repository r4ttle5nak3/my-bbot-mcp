# CLAUDE.md — BBOT MCP Server

## Project Overview

BBOT MCP Server is a Model Context Protocol (MCP) server that wraps the BBOT (Bighuge BLS OSINT Tool) reconnaissance framework, enabling AI assistants to orchestrate security reconnaissance scans through MCP tools.

## Key Files

- `mcp_server/bbot_server.py` — Main MCP server: tool registration, scan orchestration, config validation
- `mcp_server/scanner.py` — `BbotScanner` class: subprocess management, async monitoring, output parsing
- `mcp_server/__init__.py` — Package init, version info
- `mcp_server/__main__.py` — Entry point: `python -m mcp_server`
- `bbot_mcp.py` — Legacy standalone script (duplicate with `mcp_server` package)
- `tests/e2e/test_bbot_mcp_server.py` — End-to-end test suite
- `tests/fixtures.py` — Test fixtures, mock factories, test data builders
- `tests/utils.py` — Test utilities, mock implementations, assertion helpers
- `conftest.py` — Root pytest config (imports from `tests/`)
- `manual.txt` — BBOT CLI help reference (presets, flags, modules, output modules)

## Architecture

- **BbotMcpServer** (`bbot_server.py`) owns the `FastMCP` instance, registers all tools, validates configs
- **BbotScanner** (`scanner.py`) manages scan lifecycle: subprocess Popen, async IO monitoring, output persistence
- Communication: `BbotMcpServer` calls `BbotScanner` methods; `BbotScanner` spawns `bbot` CLI as subprocess

## Coding Conventions

- **Style**: PEP-8, type annotations on all functions, docstrings on every public method
- **Async**: Use `async`/`await` throughout; `BbotScanner` uses `asyncio.create_task` for process monitoring
- **Error handling**: Return `Dict[str, Any]` with `'error'` key for failures, never raise from tool methods
- **Return types**: Prefer `Dict[str, Any]` for API responses, `str` only for simple status messages
- **Imports**: Standard library first, third-party second, local third; no wildcard imports in production code
- **Logging**: Use module-level `logger` via `logging.getLogger(__name__)`
- **Config**: Defaults in `_load_config()` with optional JSON file override, deep-merged

## Testing

- Framework: `pytest` + `pytest-asyncio`
- Config: `pytest.ini` sets `--asyncio-mode=auto`
- Run: `python -m pytest tests/ -v`
- Tests use `MockProcess` / `MagicMock` to avoid real subprocess calls
- Each test class has its own fixture scope and cleanup

## Commands

- **Run server**: `python -m mcp_server`
- **Run tests**: `python -m pytest tests/ -v`
- **Syntax check**: `python -m py_compile mcp_server/bbot_server.py`

## ⚠️ Git Rules

- **Do NOT create pull requests without user approval.**
- **Do NOT create new branches without user approval.**
- **Do NOT commit or push without explicit user request.**
- All git operations require explicit user consent first.