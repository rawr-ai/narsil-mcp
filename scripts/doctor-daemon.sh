#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="${NARSIL_DAEMON_LABEL:-com.rawr.narsil-mcp-heavy}"
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
  pass "exactly one daemon-http process is running"
else
  fail "expected one daemon-http process, found $daemon_count"
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
source "$SCRIPT_DIR/resolve-daemon-env.sh" --quiet

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

  section_exists() {
    local sec="$1"
    awk -v sec="$sec" '
      $0 ~ "^\\[mcp_servers\\." sec "\\]" { found=1; exit }
      END { if (found) print "1"; else print "0" }
    ' "$CODEX_CONFIG"
  }

  section_url() {
    local sec="$1"
    awk -v sec="$sec" '
      $0 ~ "^\\[mcp_servers\\." sec "\\]" { in_sec=1; next }
      in_sec && $0 ~ "^\\[" { in_sec=0 }
      in_sec && $0 ~ /^[[:space:]]*url[[:space:]]*=/ {
        line=$0
        sub(/^[^=]*=[[:space:]]*/, "", line)
        gsub(/"/, "", line)
        gsub(/[[:space:]]+$/, "", line)
        print line
        exit
      }
    ' "$CODEX_CONFIG"
  }

  section_timeout() {
    local sec="$1"
    awk -v sec="$sec" '
      $0 ~ "^\\[mcp_servers\\." sec "\\]" { in_sec=1; next }
      in_sec && $0 ~ "^\\[" { in_sec=0 }
      in_sec && $0 ~ /^[[:space:]]*startup_timeout_sec[[:space:]]*=/ {
        line=$0
        sub(/^[^=]*=[[:space:]]*/, "", line)
        gsub(/[^0-9].*$/, "", line)
        print line
        exit
      }
    ' "$CODEX_CONFIG"
  }

  section_has_command() {
    local sec="$1"
    awk -v sec="$sec" '
      $0 ~ "^\\[mcp_servers\\." sec "\\]" { in_sec=1; next }
      in_sec && $0 ~ "^\\[" { in_sec=0 }
      in_sec && $0 ~ /^[[:space:]]*command[[:space:]]*=/ { found=1; exit }
      END { if (found) print "1"; else print "0" }
    ' "$CODEX_CONFIG"
  }

  for sec in narsil-code-intel narsil-code-intel-heavy; do
    if [[ "$(section_exists "$sec")" != "1" ]]; then
      fail "missing section [$sec] in Codex config"
      continue
    fi

    sec_url="$(section_url "$sec")"
    sec_timeout="$(section_timeout "$sec")"
    sec_has_command="$(section_has_command "$sec")"

    if [[ "$sec_url" == "$endpoint" ]]; then
      pass "[$sec] uses URL endpoint $endpoint"
    else
      fail "[$sec] url mismatch (found: ${sec_url:-none})"
    fi

    if [[ "$sec_timeout" == "120" ]]; then
      pass "[$sec] startup_timeout_sec is 120"
    else
      fail "[$sec] startup_timeout_sec is not 120 (found: ${sec_timeout:-none})"
    fi

    if [[ "$sec_has_command" == "0" ]]; then
      pass "[$sec] has no command= fallback"
    else
      fail "[$sec] contains command= (can spawn stdio instances)"
    fi
  done
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
