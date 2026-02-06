#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${NARSIL_DAEMON_ENV_FILE:-$HOME/.config/narsil-mcp/daemon.env}"
provider="voyage"
force=0
api_key=""

usage() {
  cat <<USAGE
Usage: $0 [--provider voyage|openai|custom] [--key <api-key>] [--force] [--file <path>]

Creates ~/.config/narsil-mcp/daemon.env with secure permissions for daemon credentials.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider)
      provider="$2"
      shift 2
      ;;
    --key)
      api_key="$2"
      shift 2
      ;;
    --file)
      ENV_FILE="$2"
      shift 2
      ;;
    --force)
      force=1
      shift
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

case "$provider" in
  voyage)
    key_name="VOYAGE_API_KEY"
    [[ -n "$api_key" ]] || api_key="${VOYAGE_API_KEY:-}"
    ;;
  openai)
    key_name="OPENAI_API_KEY"
    [[ -n "$api_key" ]] || api_key="${OPENAI_API_KEY:-}"
    ;;
  custom)
    key_name="EMBEDDING_API_KEY"
    [[ -n "$api_key" ]] || api_key="${EMBEDDING_API_KEY:-}"
    ;;
  *)
    echo "Invalid provider: $provider" >&2
    usage
    exit 1
    ;;
esac

mkdir -p "$(dirname "$ENV_FILE")"
chmod 700 "$(dirname "$ENV_FILE")" 2>/dev/null || true

if [[ -f "$ENV_FILE" && $force -ne 1 ]]; then
  echo "Env file already exists: $ENV_FILE"
  echo "Use --force to overwrite."
  exit 0
fi

umask 077
cat > "$ENV_FILE" <<TEMPLATE
# narsil-mcp daemon credentials
# Used by scripts/resolve-daemon-env.sh
# Keep this file private (chmod 600).

$key_name="$api_key"
TEMPLATE

chmod 600 "$ENV_FILE" 2>/dev/null || true

echo "Wrote daemon env file: $ENV_FILE"
if [[ -n "$api_key" ]]; then
  echo "Configured key variable: $key_name"
else
  echo "Configured key variable: $key_name (currently empty)"
  echo "Update $ENV_FILE with your real key before running neural mode."
fi

echo "Verify key presence (without printing value):"
echo "  rg -n '^(EMBEDDING_API_KEY|VOYAGE_API_KEY|OPENAI_API_KEY)=' '$ENV_FILE'"
