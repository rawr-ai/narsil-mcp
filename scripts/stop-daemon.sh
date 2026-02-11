#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="${NARSIL_DAEMON_LABEL:-com.rawr.narsil-mcp-heavy}"
PLIST_PATH="${NARSIL_DAEMON_PLIST:-$HOME/Library/LaunchAgents/${LABEL}.plist}"
HOST="${NARSIL_MCP_HOST:-127.0.0.1}"
PORT="${NARSIL_MCP_PORT:-12006}"
PATH_ARG="${NARSIL_MCP_PATH:-/mcp}"
GRACE_SECONDS=5

while [[ $# -gt 0 ]]; do
  case "$1" in
    --grace-seconds)
      GRACE_SECONDS="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--grace-seconds <n>]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

uid="$(id -u)"
service="gui/$uid/$LABEL"

if [[ -f "$PLIST_PATH" ]]; then
  echo "Unloading launchd service (if loaded): $service"
  launchctl bootout "gui/$uid" "$PLIST_PATH" 2>/dev/null || true
else
  echo "Launchd plist not found at $PLIST_PATH (continuing process cleanup)."
fi

target_user="$(id -un)"
endpoint="http://$HOST:$PORT$PATH_ARG"

collect_pids() {
  ps -Ao pid=,user=,args= | awk -v target_user="$target_user" -v port="$PORT" -v path_arg="$PATH_ARG" '
    {
      pid=$1; user=$2;
      $1=""; $2="";
      sub(/^ +/, "", $0);
      cmd=$0;

      if (user == target_user &&
          cmd ~ /^([^[:space:]]*\/)?narsil-mcp([[:space:]]|$)/ &&
          cmd ~ /--mcp-http/ &&
          cmd ~ ("--mcp-http-port[[:space:]]+" port) &&
          cmd ~ ("--mcp-http-path[[:space:]]+" path_arg)) {
        print pid;
      }
    }
  '
}

echo "Stopping remaining daemon-http narsil-mcp processes (if any) for $endpoint"

mapfile -t pids < <(collect_pids || true)
if [[ ${#pids[@]} -eq 0 ]]; then
  echo "No matching daemon-http processes found."
  echo "narsil-mcp daemon stopped"
  exit 0
fi

echo "Sending SIGTERM to: ${pids[*]}"
for pid in "${pids[@]}"; do
  kill -TERM "$pid" 2>/dev/null || true
done

deadline=$((SECONDS + GRACE_SECONDS))
while (( SECONDS < deadline )); do
  alive=0
  for pid in "${pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      alive=1
      break
    fi
  done
  (( alive == 0 )) && break
  sleep 0.2
done

survivors=()
for pid in "${pids[@]}"; do
  if kill -0 "$pid" 2>/dev/null; then
    survivors+=("$pid")
  fi
done

if [[ ${#survivors[@]} -gt 0 ]]; then
  echo "Sending SIGKILL to survivors: ${survivors[*]}"
  for pid in "${survivors[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
  done
fi

echo "narsil-mcp daemon stopped"
