#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="${NARSIL_DAEMON_LABEL:-com.rawr.narsil-mcp}"
PLIST_PATH="${NARSIL_DAEMON_PLIST:-$HOME/Library/LaunchAgents/${LABEL}.plist}"
WRAPPER_PATH="${NARSIL_DAEMON_WRAPPER:-$HOME/.cache/narsil-mcp/launchd-wrapper.sh}"
CODEX_HOME_PATH="${CODEX_HOME:-$HOME/.codex-rawr}"
CODEX_CONFIG_PATH="${CODEX_CONFIG_FILE:-$CODEX_HOME_PATH/config.toml}"
DAEMON_ENV_FILE="${NARSIL_DAEMON_ENV_FILE:-$HOME/.config/narsil-mcp/daemon.env}"
INDEX_PATH="${NARSIL_MCP_INDEX_PATH:-$HOME/.cache/narsil-mcp}"
HOST="${NARSIL_MCP_HOST:-127.0.0.1}"
PORT="${NARSIL_MCP_PORT:-12006}"
PATH_ARG="${NARSIL_MCP_PATH:-/mcp}"
BIN_PATH="${NARSIL_MCP_BIN:-}"
LOAD_AFTER_INSTALL=1

declare -a required_repos=()
declare -a optional_repos=()
declare -a extra_args=()

usage() {
  cat <<USAGE
Usage: $0 --repo <path> [--repo <path> ...] [options]

Options:
  --repo <path>           Repo root to index (repeatable, REQUIRED)
  --optional-repo <path>  Optional repo root to index if it exists (repeatable)
  --label <label>         launchd label (default: ${LABEL})
  --plist <path>          plist path (default: ${PLIST_PATH})
  --wrapper <path>        generated launchd wrapper path (default: ${WRAPPER_PATH})
  --bin <path>            narsil-mcp binary path (default: auto-detect)
  --index-path <path>     index cache path (default: ${INDEX_PATH})
  --host <host>           MCP HTTP host (default: ${HOST})
  --port <port>           MCP HTTP port (default: ${PORT})
  --path <path>           MCP HTTP path (default: ${PATH_ARG})
  --codex-home <path>     CODEX_HOME for daemon env fallback (default: ${CODEX_HOME_PATH})
  --env-file <path>       daemon env file path (default: ${DAEMON_ENV_FILE})
  --extra-arg <arg>       extra argument passed to narsil-mcp (repeatable)
  --no-load               only write plist and wrapper, do not load/restart service
  -h, --help              show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo|--repos)
      required_repos+=("$2")
      shift 2
      ;;
    --optional-repo)
      optional_repos+=("$2")
      shift 2
      ;;
    --label)
      LABEL="$2"
      shift 2
      ;;
    --plist)
      PLIST_PATH="$2"
      shift 2
      ;;
    --wrapper)
      WRAPPER_PATH="$2"
      shift 2
      ;;
    --bin)
      BIN_PATH="$2"
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
    --codex-home)
      CODEX_HOME_PATH="$2"
      CODEX_CONFIG_PATH="$CODEX_HOME_PATH/config.toml"
      shift 2
      ;;
    --env-file)
      DAEMON_ENV_FILE="$2"
      shift 2
      ;;
    --extra-arg)
      extra_args+=("$2")
      shift 2
      ;;
    --no-load)
      LOAD_AFTER_INSTALL=0
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

if [[ ${#required_repos[@]} -eq 0 ]]; then
  echo "At least one --repo is required." >&2
  usage
  exit 1
fi

if [[ -z "$BIN_PATH" ]]; then
  if command -v narsil-mcp >/dev/null 2>&1; then
    BIN_PATH="$(command -v narsil-mcp)"
  else
    echo "Could not find narsil-mcp on PATH. Pass --bin /absolute/path/to/narsil-mcp." >&2
    exit 1
  fi
fi

if [[ ! -x "$BIN_PATH" ]]; then
  echo "narsil-mcp binary is not executable: $BIN_PATH" >&2
  exit 1
fi

mkdir -p "$(dirname "$PLIST_PATH")"
mkdir -p "$(dirname "$WRAPPER_PATH")"
mkdir -p "$(dirname "$INDEX_PATH")"

umask 077
cat > "$WRAPPER_PATH" <<'WRAPPER_HEAD'
#!/usr/bin/env bash
set -euo pipefail

load_neural_env() {
  local env_file="$1"
  local config_file="$2"

  if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi

  if [[ -z "${EMBEDDING_API_KEY:-}" && -z "${VOYAGE_API_KEY:-}" && -z "${OPENAI_API_KEY:-}" && -f "$config_file" ]]; then
    while IFS=$'\t' read -r key value; do
      [[ -z "$key" ]] && continue
      export "$key=$value"
    done < <(sed -nE 's/^[[:space:]]*(EMBEDDING_API_KEY|VOYAGE_API_KEY|OPENAI_API_KEY)[[:space:]]*=[[:space:]]*"([^"]*)".*/\1\t\2/p' "$config_file")
  fi
}
WRAPPER_HEAD

{
  printf 'CODEX_HOME=%q\n' "$CODEX_HOME_PATH"
  printf 'NARSIL_DAEMON_ENV_FILE=%q\n' "$DAEMON_ENV_FILE"
  printf 'CODEX_CONFIG_FILE=%q\n' "$CODEX_CONFIG_PATH"
  echo 'load_neural_env "$NARSIL_DAEMON_ENV_FILE" "$CODEX_CONFIG_FILE"'
  echo ''
  echo 'declare -a REPOS_ARGS=()'
  cat <<'REPO_HELPERS'
add_required_repo() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    echo "Required repo root missing on disk: $path" >&2
    exit 1
  fi
  REPOS_ARGS+=(--repos "$path")
}

add_optional_repo() {
  local path="$1"
  if [[ -d "$path" ]]; then
    REPOS_ARGS+=(--repos "$path")
  fi
}
REPO_HELPERS

  for repo in "${required_repos[@]}"; do
    printf 'add_required_repo %q\n' "$repo"
  done

  if [[ ${optional_repos+x} && ${#optional_repos[@]} -gt 0 ]]; then
    for repo in "${optional_repos[@]}"; do
      printf 'add_optional_repo %q\n' "$repo"
    done
  fi

  cat <<'REPO_GUARD'
if [[ ${#REPOS_ARGS[@]} -eq 0 ]]; then
  echo "No configured repo roots exist on disk; refusing to start narsil-mcp." >&2
  exit 1
fi
REPO_GUARD

  printf 'exec %q ' "$BIN_PATH"
  printf '%s ' '"${REPOS_ARGS[@]}"'

  printf '%q ' \
    "--index-path" "$INDEX_PATH" \
    "--persist" "--git" "--call-graph" "--watch" \
    "--lsp" "--neural" "--neural-backend" "api" "--neural-model" "voyage-code-2" \
    "--mcp-http" "--mcp-http-host" "$HOST" "--mcp-http-port" "$PORT" "--mcp-http-path" "$PATH_ARG"

  if [[ ${extra_args+x} && ${#extra_args[@]} -gt 0 ]]; then
    for arg in "${extra_args[@]}"; do
      printf '%q ' "$arg"
    done
  fi

  printf '\n'
} >> "$WRAPPER_PATH"

chmod +x "$WRAPPER_PATH"

PLIST_DIR="$(dirname "$PLIST_PATH")"
PLIST_TMP="$(mktemp "$PLIST_DIR/.${LABEL}.XXXXXX")"

escape_xml() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  printf '%s' "$value"
}

cat > "$PLIST_TMP" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$(escape_xml "$LABEL")</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$(escape_xml "$WRAPPER_PATH")</string>
  </array>

  <key>EnvironmentVariables</key>
  <dict>
    <key>CODEX_HOME</key>
    <string>$(escape_xml "$CODEX_HOME_PATH")</string>
    <key>NARSIL_DAEMON_ENV_FILE</key>
    <string>$(escape_xml "$DAEMON_ENV_FILE")</string>
    <key>NARSIL_LAUNCHER_MANAGED</key>
    <string>1</string>
    <key>NARSIL_DAEMON_LABEL</key>
    <string>$(escape_xml "$LABEL")</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>$(escape_xml "$INDEX_PATH/launchd.stdout.log")</string>

  <key>StandardErrorPath</key>
  <string>$(escape_xml "$INDEX_PATH/launchd.stderr.log")</string>
</dict>
</plist>
XML

plutil -lint "$PLIST_TMP" >/dev/null
mv "$PLIST_TMP" "$PLIST_PATH"

echo "Wrote launchd plist: $PLIST_PATH"
echo "Wrote launchd wrapper: $WRAPPER_PATH"
echo "Label: $LABEL"

if [[ $LOAD_AFTER_INSTALL -eq 0 ]]; then
  echo "Skipped launchctl load (--no-load)."
  exit 0
fi

uid="$(id -u)"
launchctl bootout "gui/$uid" "$PLIST_PATH" 2>/dev/null || true
launchctl bootstrap "gui/$uid" "$PLIST_PATH"
launchctl enable "gui/$uid/$LABEL"
launchctl kickstart -k "gui/$uid/$LABEL"

echo "Loaded and restarted launchd service: $LABEL"
echo "Endpoint target: http://$HOST:$PORT$PATH_ARG"
