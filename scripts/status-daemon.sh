#!/usr/bin/env bash
set -euo pipefail

PID_FILE="${NARSIL_MCP_PID_FILE:-$HOME/.cache/narsil-mcp/daemon.pid}"
HOST="${NARSIL_MCP_HOST:-127.0.0.1}"
PORT="${NARSIL_MCP_PORT:-12006}"
PATH_ARG="${NARSIL_MCP_PATH:-/mcp}"

if [[ -f "$PID_FILE" ]]; then
  pid="$(cat "$PID_FILE")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "narsil-mcp daemon: running (pid: $pid)"
  else
    echo "narsil-mcp daemon: PID file exists but process is not running"
  fi
else
  echo "narsil-mcp daemon: not running (no PID file)"
fi

if command -v curl >/dev/null 2>&1; then
  url="http://$HOST:$PORT$PATH_ARG"
  if curl -fsS "$url" >/dev/null 2>&1; then
    echo "MCP endpoint reachable: $url"
  else
    echo "MCP endpoint not reachable: $url"
  fi
fi
