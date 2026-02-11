#!/usr/bin/env bash
set -euo pipefail

LABEL="${NARSIL_DAEMON_LABEL:-com.rawr.narsil-mcp}"
PLIST_PATH="${NARSIL_DAEMON_PLIST:-$HOME/Library/LaunchAgents/${LABEL}.plist}"
HOST="${NARSIL_MCP_HOST:-127.0.0.1}"
PORT="${NARSIL_MCP_PORT:-12006}"
PATH_ARG="${NARSIL_MCP_PATH:-/mcp}"

if [[ ! -f "$PLIST_PATH" ]]; then
  echo "Launchd plist not found: $PLIST_PATH" >&2
  echo "Install it with: ./scripts/install-launchd.sh --repo /absolute/path/to/repo" >&2
  exit 1
fi

uid="$(id -u)"
service="gui/$uid/$LABEL"
endpoint="http://$HOST:$PORT$PATH_ARG"

if launchctl print "$service" >/dev/null 2>&1; then
  echo "launchd service already loaded: $service"
else
  echo "Loading launchd service: $service"
  launchctl bootstrap "gui/$uid" "$PLIST_PATH"
fi

launchctl enable "$service"
launchctl kickstart "$service"

echo "Waiting for MCP endpoint: $endpoint"
for _ in {1..40}; do
  if curl -fsS "$endpoint" >/dev/null 2>&1; then
    echo "Daemon started and endpoint reachable."
    exit 0
  fi
  sleep 0.25
done

echo "Daemon started, but endpoint not yet reachable: $endpoint" >&2
exit 1
