#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="${NARSIL_DAEMON_LABEL:-com.rawr.narsil-mcp}"
PLIST_PATH="${NARSIL_DAEMON_PLIST:-$HOME/Library/LaunchAgents/${LABEL}.plist}"
HOST="${NARSIL_MCP_HOST:-127.0.0.1}"
PORT="${NARSIL_MCP_PORT:-12006}"
PATH_ARG="${NARSIL_MCP_PATH:-/mcp}"
CODEX_CONFIG="${CODEX_HOME:-$HOME/.codex-rawr}/config.toml"

pass_count=0
fail_count=0

pass() {
  echo "PASS: $*"
  pass_count=$((pass_count + 1))
}

fail() {
  echo "FAIL: $*"
  fail_count=$((fail_count + 1))
}

uid="$(id -u)"
service="gui/$uid/$LABEL"
endpoint="http://$HOST:$PORT$PATH_ARG"

if [[ -f "$PLIST_PATH" ]]; then
  pass "launchd plist exists: $PLIST_PATH"
else
  fail "launchd plist missing: $PLIST_PATH"
fi

if launchctl print "$service" >/dev/null 2>&1; then
  state="$(launchctl print "$service" 2>/dev/null | awk -F'= ' '/state =/{print $2; exit}')"
  pid="$(launchctl print "$service" 2>/dev/null | awk -F'= ' '/pid =/{print $2; exit}')"
  if [[ "$state" == "running" && -n "$pid" ]]; then
    pass "launchd service is running (pid: $pid)"
  else
    fail "launchd service loaded but not running (state: ${state:-unknown})"
  fi
else
  fail "launchd service not loaded: $service"
fi

if curl -fsS "$endpoint" >/dev/null 2>&1; then
  pass "MCP endpoint reachable: $endpoint"
else
  fail "MCP endpoint unreachable: $endpoint"
fi

daemon_count="$(ps -Ao user=,args= | awk -v target_user="$(id -un)" -v target_port="$PORT" '
  {
    user=$1
    $1=""
    sub(/^ +/, "", $0)
    cmd=$0
    if (
      user == target_user &&
      cmd ~ /^([^[:space:]]*\/)?narsil-mcp([[:space:]]|$)/ &&
      cmd ~ /--mcp-http/ &&
      cmd ~ ("--mcp-http-port[[:space:]]+" target_port "([[:space:]]|$)")
    ) {
      count++
    }
  }
  END { print count + 0 }
')"

stdio_count="$(ps -Ao user=,args= | awk -v target_user="$(id -un)" '
  {
    user=$1
    $1=""
    sub(/^ +/, "", $0)
    cmd=$0
    if (user == target_user && cmd ~ /^([^[:space:]]*\/)?narsil-mcp([[:space:]]|$)/ && cmd !~ /--mcp-http/) {
      count++
    }
  }
  END { print count + 0 }
')"

if [[ "$daemon_count" == "1" ]]; then
  pass "exactly one daemon-http process is running for port $PORT"
else
  fail "expected one daemon-http process for port $PORT, found $daemon_count"
fi

if [[ "$stdio_count" == "0" ]]; then
  pass "no stdio narsil-mcp processes detected"
else
  fail "unexpected stdio narsil-mcp processes detected: $stdio_count"
fi

saved_embedding="${EMBEDDING_API_KEY-__UNSET__}"
saved_voyage="${VOYAGE_API_KEY-__UNSET__}"
saved_openai="${OPENAI_API_KEY-__UNSET__}"

unset EMBEDDING_API_KEY VOYAGE_API_KEY OPENAI_API_KEY
# shellcheck disable=SC1091
source "$SCRIPT_DIR/resolve-daemon-env.sh"
resolve_daemon_env --quiet

if [[ -n "${EMBEDDING_API_KEY:-}" || -n "${VOYAGE_API_KEY:-}" || -n "${OPENAI_API_KEY:-}" ]]; then
  key_name="EMBEDDING_API_KEY"
  if [[ -n "${VOYAGE_API_KEY:-}" ]]; then
    key_name="VOYAGE_API_KEY"
  elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
    key_name="OPENAI_API_KEY"
  fi
  pass "neural credential available via $key_name"
else
  fail "no neural credential available to daemon"
fi

if [[ "$saved_embedding" == "__UNSET__" ]]; then unset EMBEDDING_API_KEY; else export EMBEDDING_API_KEY="$saved_embedding"; fi
if [[ "$saved_voyage" == "__UNSET__" ]]; then unset VOYAGE_API_KEY; else export VOYAGE_API_KEY="$saved_voyage"; fi
if [[ "$saved_openai" == "__UNSET__" ]]; then unset OPENAI_API_KEY; else export OPENAI_API_KEY="$saved_openai"; fi

if [[ -f "$CODEX_CONFIG" ]]; then
  pass "Codex config exists: $CODEX_CONFIG"

  while IFS='|' read -r status message; do
    [[ -z "$status" ]] && continue
    if [[ "$status" == "PASS" ]]; then
      pass "$message"
    else
      fail "$message"
    fi
  done < <(
    python3 - "$CODEX_CONFIG" "$endpoint" <<'PY'
import sys
import tomllib
from pathlib import Path

cfg_path = Path(sys.argv[1])
endpoint = sys.argv[2]

try:
    data = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"FAIL|failed to parse Codex config: {exc}")
    raise SystemExit(0)

servers = data.get("mcp_servers", {})
if not isinstance(servers, dict):
    print("FAIL|Codex config has no [mcp_servers] table")
    raise SystemExit(0)

matches = []
for name, cfg in servers.items():
    if isinstance(cfg, dict) and cfg.get("url") == endpoint:
        matches.append((name, cfg))

if not matches:
    print(f"FAIL|no [mcp_servers.*] entry points to {endpoint}")
    raise SystemExit(0)

for name, cfg in matches:
    print(f"PASS|[{name}] uses URL endpoint {endpoint}")
    timeout = cfg.get("startup_timeout_sec")
    if timeout == 120:
        print(f"PASS|[{name}] startup_timeout_sec is 120")
    else:
        print(f"FAIL|[{name}] startup_timeout_sec is not 120 (found: {timeout!r})")
    if "command" in cfg:
        print(f"FAIL|[{name}] contains command= (can spawn stdio instances)")
    else:
        print(f"PASS|[{name}] has no command= fallback")
PY
  )
else
  fail "Codex config missing: $CODEX_CONFIG"
fi

echo
if (( fail_count == 0 )); then
  echo "Doctor result: healthy ($pass_count checks passed)"
  exit 0
fi

echo "Doctor result: issues found (passes=$pass_count, fails=$fail_count)"
exit 1
