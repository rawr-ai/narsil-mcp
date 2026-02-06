#!/usr/bin/env bash
set -euo pipefail

DAEMON_ENV_FILE_DEFAULT="$HOME/.config/narsil-mcp/daemon.env"
CODEX_CONFIG_FILE_DEFAULT="${CODEX_HOME:-$HOME/.codex-rawr}/config.toml"

strip_outer_quotes() {
  local value="$1"
  value="${value#${value%%[![:space:]]*}}"
  value="${value%${value##*[![:space:]]}}"

  if [[ "$value" =~ ^\"(.*)\"$ ]]; then
    value="${BASH_REMATCH[1]}"
  elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
    value="${BASH_REMATCH[1]}"
  fi

  printf '%s' "$value"
}

load_from_env_file() {
  local env_file="$1"
  local loaded=0

  [[ -f "$env_file" ]] || return 1

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
      local key="${BASH_REMATCH[1]}"
      local raw_value="${BASH_REMATCH[2]}"
      local value
      value="$(strip_outer_quotes "$raw_value")"

      case "$key" in
        EMBEDDING_API_KEY|VOYAGE_API_KEY|OPENAI_API_KEY)
          export "$key=$value"
          if [[ -n "$value" ]]; then
            loaded=1
          fi
          ;;
      esac
    fi
  done < "$env_file"

  (( loaded == 1 ))
}

load_from_codex_config() {
  local config_file="$1"
  local loaded=0

  [[ -f "$config_file" ]] || return 1

  while IFS=$'\t' read -r key value; do
    [[ -z "$key" ]] && continue
    export "$key=$value"
    loaded=1
  done < <(sed -nE 's/^[[:space:]]*(EMBEDDING_API_KEY|VOYAGE_API_KEY|OPENAI_API_KEY)[[:space:]]*=[[:space:]]*"([^"]*)".*/\1\t\2/p' "$config_file")

  (( loaded == 1 ))
}

has_embedding_key() {
  [[ -n "${EMBEDDING_API_KEY:-}" || -n "${VOYAGE_API_KEY:-}" || -n "${OPENAI_API_KEY:-}" ]]
}

resolve_daemon_env() {
  local quiet=0
  local daemon_env_file="${NARSIL_DAEMON_ENV_FILE:-$DAEMON_ENV_FILE_DEFAULT}"
  local codex_config_file="${CODEX_CONFIG_FILE:-$CODEX_CONFIG_FILE_DEFAULT}"
  local neural_required="${NARSIL_NEURAL_REQUIRED:-0}"
  local source_used="none"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --quiet)
        quiet=1
        shift
        ;;
      --env-file)
        daemon_env_file="$2"
        shift 2
        ;;
      --codex-config)
        codex_config_file="$2"
        shift 2
        ;;
      --neural-required)
        neural_required=1
        shift
        ;;
      *)
        echo "Unknown argument: $1" >&2
        return 2
        ;;
    esac
  done

  if load_from_env_file "$daemon_env_file"; then
    source_used="daemon-env"
    (( quiet == 1 )) || echo "Loaded daemon credentials from $daemon_env_file"
  elif load_from_codex_config "$codex_config_file"; then
    source_used="codex-config"
    (( quiet == 1 )) || echo "Warning: loaded credentials from $codex_config_file (migration fallback)."
    (( quiet == 1 )) || echo "Create $daemon_env_file and move keys there for stable daemon runtime."
  else
    source_used="none"
    (( quiet == 1 )) || echo "Warning: no daemon credential source found (checked $daemon_env_file, $codex_config_file)."
  fi

  if (( neural_required == 1 )) && ! has_embedding_key; then
    echo "Warning: --neural is enabled but no EMBEDDING_API_KEY/VOYAGE_API_KEY/OPENAI_API_KEY is set." >&2
  fi

  export NARSIL_DAEMON_ENV_SOURCE="$source_used"

  if (( quiet == 0 )); then
    local key_name="none"
    if [[ -n "${EMBEDDING_API_KEY:-}" ]]; then
      key_name="EMBEDDING_API_KEY"
    elif [[ -n "${VOYAGE_API_KEY:-}" ]]; then
      key_name="VOYAGE_API_KEY"
    elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
      key_name="OPENAI_API_KEY"
    fi
    echo "Resolved key variable: $key_name"
  fi

  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  resolve_daemon_env "$@"
fi
