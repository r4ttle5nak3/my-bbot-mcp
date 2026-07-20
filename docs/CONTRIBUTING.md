# Contributing to BBOT MCP Server

Thank you for your interest in contributing! This guide will help you get started.

## Code of Conduct

Be respectful, collaborative, and constructive. We're building tools for authorized security testing only.

## How to Contribute

### 1. Fork and Clone

```bash
git clone https://github.com/your-username/my-bbot-mcp.git
cd my-bbot-mcp
```

### 2. Set Up Development Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install mcp pytest pytest-asyncio
```

### 3. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 4. Make Your Changes

Follow these guidelines:

- **Code Style**: Follow PEP-8
- **Documentation**: Add docstrings to all functions
- **Type Hints**: Use type annotations
- **Error Handling**: Handle exceptions gracefully

### 5. Write Tests

All new functionality must include tests:

```bash
# Run tests
python -m pytest tests/ -v

# Check coverage
python -m pytest tests/ --cov=mcp_server
```

### 6. Commit and Push

```bash
git add .
git commit -m "feat: add your feature description"
git push origin feature/your-feature-name
```

### 7. Open a Pull Request

Provide a clear description of your changes and reference any related issues.

## Development Guidelines

### Project Structure

```
mcp_server/       # Core implementation
├── scanner.py    # BBOT process management
├── bbot_server.py # MCP tools
└── docs/         # Doc generation

tests/            # Test suite
├── e2e/          # End-to-end tests
├── fixtures.py   # Test fixtures
└── utils.py      # Test helpers
```

### Adding a New Tool

1. Add the method to `BbotMcpServer` in `bbot_server.py`
2. Decorate with `@mcp.tool()`
3. Add comprehensive docstring
4. Write tests in `tests/e2e/`
5. Update API documentation

Example:

```python
@mcp.tool()
async def my_new_tool(self, param: str) -> Dict[str, Any]:
    """
    Description of what the tool does.

    Args:
        param: Description of parameter

    Returns:
        Description of return value
    """
    try:
        # Implementation
        return {"result": "success"}
    except Exception as e:
        return {"error": str(e)}
```

### Testing Standards

- Write tests for happy path and error cases
- Mock external dependencies (subprocess, network)
- Aim for >80% code coverage
- Use descriptive test names

### Commit Message Convention

Follow conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

## Reporting Issues

When reporting issues, include:

1. Description of the problem
2. Steps to reproduce
3. Expected vs actual behavior
4. Environment details (OS, Python version)
5. Relevant logs or error messages

## Security Vulnerabilities

For security issues, please email the maintainers directly rather than opening a public issue.

## Questions?

Open a discussion or issue for any questions about contributing.

Thank you for helping make BBOT MCP Server better!