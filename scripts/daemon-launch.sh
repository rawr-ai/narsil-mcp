#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST="${NARSIL_MCP_HOST:-127.0.0.1}"
PORT="${NARSIL_MCP_PORT:-12006}"
PATH_ARG="${NARSIL_MCP_PATH:-/mcp}"
INDEX_PATH="${NARSIL_MCP_INDEX_PATH:-$HOME/.cache/narsil-mcp}"
NARSIL_BIN="${NARSIL_MCP_BIN:-}"
NEURAL_MODEL="${NARSIL_NEURAL_MODEL:-voyage-code-3}"

declare -a repos=()
declare -a passthrough=()

usage() {
  cat <<USAGE
Usage: $0 [--repo <path>]... [--index-path <path>] [--host <host>] [--port <port>] [--path <path>] [--bin <binary>] [--neural-model <model>] [-- <extra narsil args>]

Notes:
  - Heavy daemon flags are enabled by default: --watch --lsp --neural --git --call-graph --persist
  - Repos can also be supplied via NARSIL_DAEMON_REPOS as comma-separated paths.
  - Neural model defaults to NARSIL_NEURAL_MODEL or voyage-code-3.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo|--repos)
      repos+=("$2")
      shift 2
      ;;
    --index-path)
      INDEX_PATH="$2"
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
    --bin)
      NARSIL_BIN="$2"
      shift 2
      ;;
    --neural-model)
      NEURAL_MODEL="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      passthrough+=("$@")
      break
      ;;
    *)
      passthrough+=("$1")
      shift
      ;;
  esac
done

if [[ ${#repos[@]} -eq 0 && -n "${NARSIL_DAEMON_REPOS:-}" ]]; then
  IFS=',' read -r -a repos <<<"${NARSIL_DAEMON_REPOS}"
fi

if [[ ${#repos[@]} -eq 0 ]]; then
  echo "No repos configured. Pass --repo /path/to/repo (repeatable) or set NARSIL_DAEMON_REPOS." >&2
  exit 1
fi

for i in "${!repos[@]}"; do
  repos[$i]="${repos[$i]%/}"
done

if [[ -z "$NARSIL_BIN" ]]; then
  if command -v narsil-mcp >/dev/null 2>&1; then
    NARSIL_BIN="$(command -v narsil-mcp)"
  elif [[ -x "$REPO_ROOT/target/release/narsil-mcp" ]]; then
    NARSIL_BIN="$REPO_ROOT/target/release/narsil-mcp"
  elif [[ -x "$REPO_ROOT/target/debug/narsil-mcp" ]]; then
    NARSIL_BIN="$REPO_ROOT/target/debug/narsil-mcp"
  fi
fi

if [[ -z "$NARSIL_BIN" ]]; then
  echo "Could not find narsil-mcp binary. Set NARSIL_MCP_BIN or pass --bin." >&2
  exit 1
fi

if [[ ! -x "$NARSIL_BIN" ]]; then
  echo "narsil-mcp binary is not executable: $NARSIL_BIN" >&2
  exit 1
fi

export NARSIL_NEURAL_REQUIRED=1
# shellcheck disable=SC1091
source "$SCRIPT_DIR/resolve-daemon-env.sh"
resolve_daemon_env --quiet

cmd=("$NARSIL_BIN")
for repo in "${repos[@]}"; do
  cmd+=("--repos" "$repo")
done

cmd+=(
  "--index-path" "$INDEX_PATH"
  "--persist"
  "--git"
  "--call-graph"
  "--watch"
  "--lsp"
  "--neural"
  "--neural-backend" "api"
  "--neural-model" "$NEURAL_MODEL"
  "--mcp-http"
  "--mcp-http-host" "$HOST"
  "--mcp-http-port" "$PORT"
  "--mcp-http-path" "$PATH_ARG"
)

cmd+=("${passthrough[@]}")

echo "Starting narsil-mcp shared daemon"
echo "- binary: $NARSIL_BIN"
echo "- repos: ${#repos[@]}"
echo "- endpoint: http://$HOST:$PORT$PATH_ARG"
echo "- env source: ${NARSIL_DAEMON_ENV_SOURCE:-unknown}"

exec "${cmd[@]}"
