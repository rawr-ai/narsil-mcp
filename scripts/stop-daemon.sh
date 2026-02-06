#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="${NARSIL_DAEMON_LABEL:-com.rawr.narsil-mcp-heavy}"
PLIST_PATH="${NARSIL_DAEMON_PLIST:-$HOME/Library/LaunchAgents/${LABEL}.plist}"
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

echo "Stopping remaining narsil-mcp processes..."
"$SCRIPT_DIR/shutdown-all.sh" --grace-seconds "$GRACE_SECONDS"

echo "narsil-mcp daemon stopped"
