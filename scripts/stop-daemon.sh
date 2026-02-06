#!/usr/bin/env bash
set -euo pipefail

PID_FILE="${NARSIL_MCP_PID_FILE:-$HOME/.cache/narsil-mcp/daemon.pid}"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found at $PID_FILE"
  exit 0
fi

pid="$(cat "$PID_FILE")"
if [[ -z "$pid" ]]; then
  rm -f "$PID_FILE"
  echo "PID file was empty; cleaned up."
  exit 0
fi

if kill -0 "$pid" 2>/dev/null; then
  echo "Stopping narsil-mcp daemon (pid: $pid)..."
  kill "$pid"

  for _ in {1..20}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done

  if kill -0 "$pid" 2>/dev/null; then
    echo "Process still running; sending SIGKILL"
    kill -9 "$pid" || true
  fi
else
  echo "Process $pid is not running"
fi

rm -f "$PID_FILE"
echo "narsil-mcp daemon stopped"
