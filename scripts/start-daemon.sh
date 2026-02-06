#!/usr/bin/env bash
set -euo pipefail

PID_FILE="${NARSIL_MCP_PID_FILE:-$HOME/.cache/narsil-mcp/daemon.pid}"
LOG_FILE="${NARSIL_MCP_LOG_FILE:-$HOME/.cache/narsil-mcp/daemon.log}"
HOST="${NARSIL_MCP_HOST:-127.0.0.1}"
PORT="${NARSIL_MCP_PORT:-12006}"
PATH_ARG="${NARSIL_MCP_PATH:-/mcp}"
INDEX_PATH="${NARSIL_MCP_INDEX_PATH:-$HOME/.cache/narsil-mcp}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

mkdir -p "$(dirname "$PID_FILE")"
mkdir -p "$(dirname "$LOG_FILE")"

if [[ -f "$PID_FILE" ]]; then
  existing_pid="$(cat "$PID_FILE")"
  if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
    echo "narsil-mcp daemon already running (pid: $existing_pid)"
    exit 0
  fi
  rm -f "$PID_FILE"
fi

if [[ "$#" -eq 0 ]]; then
  echo "Usage: $0 --repos /path/to/repo [--repos /path/to/other] [extra narsil-mcp args...]"
  echo "Tip: pass repo roots explicitly; avoid broad discover roots for daemon mode."
  exit 1
fi

if [[ -n "${NARSIL_MCP_BIN:-}" ]]; then
  cmd=("${NARSIL_MCP_BIN}")
elif [[ -x "$REPO_ROOT/target/debug/narsil-mcp" ]]; then
  cmd=("$REPO_ROOT/target/debug/narsil-mcp")
elif [[ -x "$REPO_ROOT/target/release/narsil-mcp" ]]; then
  cmd=("$REPO_ROOT/target/release/narsil-mcp")
elif command -v cargo >/dev/null 2>&1; then
  cmd=("cargo" "run" "--release" "--bin" "narsil-mcp" "--")
else
  echo "Could not find narsil-mcp binary."
  echo "Set NARSIL_MCP_BIN=/absolute/path/to/narsil-mcp or build locally with cargo."
  exit 1
fi

cmd+=(
  "--mcp-http"
  "--mcp-http-host" "$HOST"
  "--mcp-http-port" "$PORT"
  "--mcp-http-path" "$PATH_ARG"
  "--index-path" "$INDEX_PATH"
  "--persist"
)

cmd+=("$@")

echo "Starting narsil-mcp daemon: ${cmd[*]}"
nohup "${cmd[@]}" >>"$LOG_FILE" 2>&1 &
pid=$!
echo "$pid" > "$PID_FILE"

echo "Started narsil-mcp daemon (pid: $pid)"
echo "MCP endpoint: http://$HOST:$PORT$PATH_ARG"
echo "Log file: $LOG_FILE"
