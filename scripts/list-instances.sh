#!/usr/bin/env bash
set -euo pipefail

target_user="$(id -un)"

collect_instances() {
  ps -Ao pid=,ppid=,user=,rss=,etime=,args= | awk -v target_user="$target_user" '
    {
      pid=$1; ppid=$2; user=$3; rss=$4; etime=$5;
      $1=""; $2=""; $3=""; $4=""; $5="";
      sub(/^ +/, "", $0);
      cmd=$0;

      if (user == target_user && cmd ~ /(^|[[:space:]])([^[:space:]]*\/)?narsil-mcp([[:space:]]|$)/) {
        print pid "\t" ppid "\t" rss "\t" etime "\t" cmd;
      }
    }
  '
}

classify_mode() {
  local cmd="$1"
  if [[ "$cmd" == *"--mcp-http"* ]]; then
    echo "daemon-http"
  elif [[ "$cmd" == *"--watch"* || "$cmd" == *"--lsp"* || "$cmd" == *"--neural"* ]]; then
    echo "stdio-heavy"
  else
    echo "stdio"
  fi
}

extract_repo_hint() {
  local cmd="$1"
  if [[ "$cmd" =~ --repos[[:space:]]+([^[:space:]]+) ]]; then
    echo "${BASH_REMATCH[1]}"
  else
    echo "-"
  fi
}

lines=()
while IFS= read -r line; do
  lines+=("$line")
done < <(collect_instances)

if [[ ${#lines[@]} -eq 0 ]]; then
  echo "No running narsil-mcp processes found."
  exit 0
fi

printf "%-8s %-8s %-8s %-10s %-12s %-30s %s\n" "PID" "PPID" "RSS_MB" "ELAPSED" "MODE" "REPO_HINT" "COMMAND"

for line in "${lines[@]}"; do
  IFS=$'\t' read -r pid ppid rss_kb elapsed cmd <<<"$line"
  [[ -z "$pid" ]] && continue

  rss_mb="$(awk -v rss_kb="$rss_kb" 'BEGIN { printf "%.1f", rss_kb / 1024 }')"
  mode="$(classify_mode "$cmd")"
  repo_hint="$(extract_repo_hint "$cmd")"

  printf "%-8s %-8s %-8s %-10s %-12s %-30s %s\n" "$pid" "$ppid" "$rss_mb" "$elapsed" "$mode" "$repo_hint" "$cmd"
done

exit 0
