#!/bin/bash

# BBOT MCP Server Startup Script
# This script initializes and starts the BBOT MCP server

set -e  # Exit on error

# Configuration
VENV_PATH="${VENV_PATH:-./venv}"
CONFIG_FILE="${CONFIG_FILE:-./mcp_server/config/server.json}"
HOST="${HOST:-localhost}"
PORT="${PORT:-8080}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
BBOT_MCP_PATH="${BBOT_MCP_PATH:-./bbot_mcp.py}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if virtual environment exists
if [ ! -d "$VENV_PATH" ]; then
    print_info "Creating virtual environment..."
    python3 -m venv "$VENV_PATH"
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source "$VENV_PATH/bin/activate"

# Install/update dependencies
print_info "Installing dependencies..."
pip install --quiet mcp

# Create scan output directory
mkdir -p scan_outputs

# Display server configuration
print_info "Starting BBOT MCP Server..."
echo "   Host: $HOST"
echo "   Port: $PORT"
echo "   Log Level: $LOG_LEVEL"
echo "   Config File: $CONFIG_FILE"
echo ""

# Run the server
print_info "Server starting at http://$HOST:$PORT"
python -m mcp_server

# Graceful shutdown handler
trap 'print_info "Shutting down MCP server gracefully..."; exit 0' INT TERM

print_info "Server stopped."