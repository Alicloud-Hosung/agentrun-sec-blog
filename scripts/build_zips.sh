#!/usr/bin/env bash
# Package each service as a flat zip for Function Compute (custom runtime).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
rm -f dist/ticket-mcp.zip dist/hook-service.zip
(cd mcp_server && zip -q ../dist/ticket-mcp.zip server.py)
(cd hook_service && zip -q ../dist/hook-service.zip hook.py)
ls -l dist
