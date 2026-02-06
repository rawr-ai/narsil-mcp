#!/usr/bin/env bash
set -euo pipefail

dry_run=false
force=false
repo_filter=""
grace_seconds=5

target_user="$(id -un)"
self_pid="$$"
self_ppid="$PPID"
pid_file="${NARSIL_MCP_PID_FILE:-$HOME/.cache/narsil-mcp/daemon.pid}"

usage() {
  cat <<USAGE
Usage: $0 [--dry-run] [--repo <substring>] [--grace-seconds <n>] [--force]

Options:
  --dry-run            Show matched processes but do not send signals
  --repo <substring>   Only target processes whose command contains substring
  --grace-seconds <n>  Seconds to wait after SIGTERM before SIGKILL (default: 5)
  --force              Send SIGKILL immediately (skip SIGTERM/grace wait)
  -h, --help           Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      dry_run=true
      shift
      ;;
    --repo)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --repo"
        usage
        exit 1
      fi
      repo_filter="$2"
      shift 2
      ;;
    --grace-seconds)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --grace-seconds"
        usage
        exit 1
      fi
      grace_seconds="$2"
      if ! [[ "$grace_seconds" =~ ^[0-9]+$ ]]; then
        echo "--grace-seconds must be a non-negative integer"
        exit 1
      fi
      shift 2
      ;;
    --force)
      force=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

collect_instances() {
  ps -Ao pid=,ppid=,user=,rss=,etime=,args= | awk -v target_user="$target_user" '
    {
      pid=$1; ppid=$2; user=$3; rss=$4; etime=$5;
      $1=""; $2=""; $3=""; $4=""; $5="";
      sub(/^ +/, "", $0);
      cmd=$0;

      if (user == target_user && cmd ~ /^([^[:space:]]*\/)?narsil-mcp([[:space:]]|$)/) {
        print pid "\t" ppid "\t" rss "\t" etime "\t" cmd;
      }
    }
  '
}

print_targets() {
  if [[ ${#target_lines[@]} -eq 0 ]]; then
    return
  fi

  printf "%-8s %-8s %-8s %-10s %-12s %-30s %s\n" "PID" "PPID" "RSS_MB" "ELAPSED" "MODE" "REPO_HINT" "COMMAND"

  for line in "${target_lines[@]}"; do
    IFS=$'\t' read -r pid ppid rss_kb elapsed cmd <<<"$line"
    [[ -z "$pid" ]] && continue

    rss_mb="$(awk -v rss_kb="$rss_kb" 'BEGIN { printf "%.1f", rss_kb / 1024 }')"

    mode="stdio"
    if [[ "$cmd" == *"--mcp-http"* ]]; then
      mode="daemon-http"
    elif [[ "$cmd" == *"--watch"* || "$cmd" == *"--lsp"* || "$cmd" == *"--neural"* ]]; then
      mode="stdio-heavy"
    fi

    repo_hint="-"
    if [[ "$cmd" =~ --repos[[:space:]]+([^[:space:]]+) ]]; then
      repo_hint="${BASH_REMATCH[1]}"
    fi

    printf "%-8s %-8s %-8s %-10s %-12s %-30s %s\n" "$pid" "$ppid" "$rss_mb" "$elapsed" "$mode" "$repo_hint" "$cmd"
  done
}

declare -a discovered=()
while IFS= read -r line; do
  discovered+=("$line")
done < <(collect_instances)

declare -a target_lines=()
declare -a target_pids=()
matched=0
set +u
for line in "${discovered[@]}"; do
  IFS=$'\t' read -r pid ppid _rss _elapsed cmd <<<"$line"
  [[ -z "$pid" ]] && continue

  if [[ "$pid" == "$self_pid" || "$pid" == "$self_ppid" ]]; then
    continue
  fi

  if [[ -n "$repo_filter" && "$cmd" != *"$repo_filter"* ]]; then
    continue
  fi

  target_lines+=("$line")
  target_pids+=("$pid")
  matched=$((matched + 1))
done
set -u

terminated_term=0
terminated_kill=0
failed=0

if [[ $matched -eq 0 ]]; then
  echo "No matching narsil-mcp processes found."
  echo "Summary: matched=0 terminated_term=0 terminated_kill=0 failed=0"

  if [[ -f "$pid_file" ]]; then
    daemon_pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ -z "$daemon_pid" ]] || ! kill -0 "$daemon_pid" 2>/dev/null; then
      rm -f "$pid_file"
      echo "Cleaned stale daemon PID file: $pid_file"
    fi
  fi

  exit 0
fi

if [[ -n "$repo_filter" ]]; then
  echo "Target filter: repo substring '$repo_filter'"
else
  echo "Target filter: all current-user narsil-mcp processes"
fi

print_targets

if $dry_run; then
  echo "Dry run: no signals sent."
  echo "Summary: matched=$matched terminated_term=0 terminated_kill=0 failed=0"
  exit 0
fi

if $force; then
  for pid in "${target_pids[@]}"; do
    kill -KILL "$pid" 2>/dev/null || true
  done
  sleep 0.2

  for pid in "${target_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      failed=$((failed + 1))
    else
      terminated_kill=$((terminated_kill + 1))
    fi
  done
else
  for pid in "${target_pids[@]}"; do
    kill -TERM "$pid" 2>/dev/null || true
  done

  deadline=$((SECONDS + grace_seconds))
  while (( SECONDS < deadline )); do
    any_alive=0
    for pid in "${target_pids[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        any_alive=1
        break
      fi
    done

    if (( any_alive == 0 )); then
      break
    fi

    sleep 0.2
  done

  declare -a survivors=()
  for pid in "${target_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      survivors+=("$pid")
    else
      terminated_term=$((terminated_term + 1))
    fi
  done

  if [[ ${#survivors[@]} -gt 0 ]]; then
    for pid in "${survivors[@]}"; do
      kill -KILL "$pid" 2>/dev/null || true
    done
    sleep 0.2

    for pid in "${survivors[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        failed=$((failed + 1))
      else
        terminated_kill=$((terminated_kill + 1))
      fi
    done
  fi
fi

if [[ -f "$pid_file" ]]; then
  daemon_pid="$(cat "$pid_file" 2>/dev/null || true)"
  if [[ -z "$daemon_pid" ]] || ! kill -0 "$daemon_pid" 2>/dev/null; then
    rm -f "$pid_file"
    echo "Cleaned stale daemon PID file: $pid_file"
  fi
fi

scope_survivors=0
for pid in "${target_pids[@]}"; do
  if kill -0 "$pid" 2>/dev/null; then
    scope_survivors=$((scope_survivors + 1))
  fi
done

echo "Summary: matched=$matched terminated_term=$terminated_term terminated_kill=$terminated_kill failed=$failed"

if (( scope_survivors == 0 )); then
  exit 0
fi

echo "Error: $scope_survivors targeted process(es) are still running."
exit 1
