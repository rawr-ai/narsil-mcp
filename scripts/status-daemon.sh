#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="${NARSIL_DAEMON_LABEL:-com.rawr.narsil-mcp}"
HOST="${NARSIL_MCP_HOST:-127.0.0.1}"
PORT="${NARSIL_MCP_PORT:-12006}"
PATH_ARG="${NARSIL_MCP_PATH:-/mcp}"

uid="$(id -u)"
service="gui/$uid/$LABEL"
endpoint="http://$HOST:$PORT$PATH_ARG"

echo "Service: $service"
if launchctl print "$service" >/dev/null 2>&1; then
  state="$(launchctl print "$service" 2>/dev/null | awk -F'= ' '/state =/{print $2; exit}')"
  pid="$(launchctl print "$service" 2>/dev/null | awk -F'= ' '/pid =/{print $2; exit}')"
  echo "launchd state: ${state:-unknown}"
  [[ -n "$pid" ]] && echo "launchd pid: $pid"
else
  echo "launchd state: not loaded"
fi

if curl -fsS "$endpoint" >/dev/null 2>&1; then
  echo "endpoint: reachable ($endpoint)"
else
  echo "endpoint: not reachable ($endpoint)"
fi

echo
exit 0
