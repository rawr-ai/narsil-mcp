#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="${NARSIL_DAEMON_LABEL:-com.rawr.narsil-mcp-heavy}"
PLIST_PATH="${NARSIL_DAEMON_PLIST:-$HOME/Library/LaunchAgents/${LABEL}.plist}"
HOST="${NARSIL_MCP_HOST:-127.0.0.1}"
PORT="${NARSIL_MCP_PORT:-12006}"
PATH_ARG="${NARSIL_MCP_PATH:-/mcp}"
GRACE_SECONDS=5

usage() {
  cat <<USAGE
Usage: $0 [--label <label>] [--plist <path>] [--host <host>] [--port <port>] [--path <path>] [--grace-seconds <n>]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --label)
      LABEL="$2"
      shift 2
      ;;
    --plist)
      PLIST_PATH="$2"
      shift 2
      ;;
    --host)
      HOST="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --path)
      PATH_ARG="$2"
      shift 2
      ;;
    --grace-seconds)
      GRACE_SECONDS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ! -f "$PLIST_PATH" ]]; then
  echo "Launchd plist not found: $PLIST_PATH" >&2
  echo "Run ./scripts/install-launchd.sh --repo /path/to/repo first." >&2
  exit 1
fi

uid="$(id -u)"
service="gui/$uid/$LABEL"
endpoint="http://$HOST:$PORT$PATH_ARG"

echo "Stopping launchd service (if loaded): $service"
launchctl bootout "gui/$uid" "$PLIST_PATH" 2>/dev/null || true

echo "Shutting down remaining narsil-mcp processes"
"$SCRIPT_DIR/shutdown-all.sh" --grace-seconds "$GRACE_SECONDS"

echo "Starting launchd service: $service"
launchctl bootstrap "gui/$uid" "$PLIST_PATH"
launchctl enable "$service"
launchctl kickstart -k "$service"

echo "Waiting for MCP endpoint: $endpoint"
for _ in {1..40}; do
  if curl -fsS "$endpoint" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

if ! curl -fsS "$endpoint" >/dev/null 2>&1; then
  echo "Endpoint did not become reachable: $endpoint" >&2
  exit 1
fi

daemon_count="$(ps -Ao user=,args= | awk -v target_user="$(id -un)" '
  {
    user=$1
    $1=""
    sub(/^ +/, "", $0)
    cmd=$0
    if (user == target_user && cmd ~ /^([^[:space:]]*\/)?narsil-mcp([[:space:]]|$)/ && cmd ~ /--mcp-http/) {
      count++
    }
  }
  END { print count + 0 }
')"

if [[ "$daemon_count" != "1" ]]; then
  echo "Expected exactly one daemon-http process after restart, found: $daemon_count" >&2
  "$SCRIPT_DIR/list-instances.sh" || true
  exit 1
fi

echo "Restart complete. Endpoint healthy and single daemon process confirmed."
