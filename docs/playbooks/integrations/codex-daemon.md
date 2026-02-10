# Codex Shared Daemon (OOM-Friendly)

Use one long-lived `narsil-mcp` process and connect Codex via `url` transport so new Codex sessions do not spawn new heavy stdio servers.

## Why This Setup Is Required

In stdio mode, each MCP client process launches its own `narsil-mcp` instance.
With multiple sessions/threads, memory usage multiplies.

In URL mode (`mcp-http`), Codex connects to a shared daemon. This prevents per-session spawning.

Important credential rule:

- Codex URL transport does **not** inject per-server env vars for `narsil-mcp`.
- Neural API keys must be provided by the daemon launch environment.
- Canonical location: `~/.config/narsil-mcp/daemon.env`.

## Canonical Runbook (macOS launchd)

### 1) Create daemon env file (once)

```bash
./scripts/setup-daemon-env.sh --provider voyage --key 'pa-...'
```

This writes:

- `~/.config/narsil-mcp/daemon.env` (mode `600`)

### 2) Install/update launchd service (single instance)

```bash
./scripts/install-launchd.sh \
  --repo /absolute/path/to/repo-a \
  --repo /absolute/path/to/repo-b
```

This writes and loads:

- `~/Library/LaunchAgents/com.rawr.narsil-mcp-heavy.plist`
- `~/.cache/narsil-mcp/launchd-wrapper.sh` (launchd-safe wrapper script)

The launchd wrapper runs `narsil-mcp` with daemon defaults and:

- resolves credentials from `~/.config/narsil-mcp/daemon.env` (with codex config fallback),
- starts `narsil-mcp` with heavy daemon defaults,
- serves MCP on `http://127.0.0.1:12006/mcp`.

### 2b) Install/update multiple daemons from one config (recommended for multi-domain)

If you want **one permanent place** to define:

- how many daemons exist,
- which ports they run on,
- which repo roots they index,

use an instances config file and apply it:

```bash
# Example schema (safe to commit/share)
cat ./configs/daemon-instances.example.toml

# Your real config (recommended location)
$EDITOR ~/.config/narsil-mcp/instances.toml

# Apply config (writes plists/wrappers; restarts services by default)
./scripts/apply-instances.py
```

Notes:

- Required `repos` must exist on disk; `optional_repos` may be missing.
- The generated launchd wrapper treats configured roots as "optional if missing" at runtime so the daemon can start before generated outputs exist.

### 3) Restart cleanly

```bash
./scripts/restart-daemon.sh
```

`restart-daemon.sh` performs:

1. unload launchd service,
2. `shutdown-all.sh` to remove lingering `narsil-mcp` processes,
3. bootstrap/enable/kickstart launchd,
4. endpoint health check and single-daemon verification.

If you are running multiple daemons, prefer per-label launchd restarts instead of `restart-daemon.sh` (which assumes a single daemon and may stop other instances):

```bash
launchctl kickstart -k "gui/$(id -u)/com.rawr.narsil-mcp-domain-a"
launchctl kickstart -k "gui/$(id -u)/com.rawr.narsil-mcp-domain-b"
```

### 4) Validate configuration and runtime

```bash
./scripts/doctor-daemon.sh
```

Doctor verifies:

- launchd service loaded/running,
- MCP endpoint reachable,
- exactly one daemon-http process,
- no stdio `narsil-mcp` processes,
- neural key available (without printing secret),
- Codex config URL-only with `startup_timeout_sec = 120`.

## Daily Operator Commands

```bash
# Start launchd daemon
./scripts/start-daemon.sh

# Stop launchd daemon and all lingering narsil processes
./scripts/stop-daemon.sh

# Restart with clean shutdown + health checks
./scripts/restart-daemon.sh

# Service + endpoint + instance table
./scripts/status-daemon.sh

# List all current-user narsil-mcp instances (daemon + stdio)
./scripts/list-instances.sh

# Kill all current-user narsil-mcp instances
./scripts/shutdown-all.sh

# Preview kills only
./scripts/shutdown-all.sh --dry-run

# Kill only matching repo command lines
./scripts/shutdown-all.sh --repo /absolute/path/to/repo
```

## Codex Config Contract (`~/.codex-rawr/config.toml`)

Use URL-only entries for both profiles:

```toml
[mcp_servers.narsil-code-intel]
url = "http://127.0.0.1:12006/mcp"
startup_timeout_sec = 120

[mcp_servers.narsil-code-intel-heavy]
url = "http://127.0.0.1:12006/mcp"
startup_timeout_sec = 120
```

Do not set `command = "...narsil-mcp"` for these sections.
That re-enables per-session stdio spawning and can reintroduce OOM pressure.

## Stable Repo IDs

`list_repos` returns stable repo IDs as:

- `<basename>#<short_hash>`

Use `repo_id` when possible, especially with same-named repos.

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| Multiple `narsil-mcp` processes | Codex config still has command-based entries | Remove command entries; keep URL-only; run `./scripts/restart-daemon.sh` |
| `401 Unauthorized` for neural rebuild | Daemon missing/invalid API key | Update `~/.config/narsil-mcp/daemon.env`; restart daemon |
| Endpoint down | launchd service not loaded/running | Run `./scripts/start-daemon.sh` or reinstall with `./scripts/install-launchd.sh` |
| Doctor fails URL/timeout checks | Config drift in `.codex-rawr/config.toml` | Set both sections to URL `http://127.0.0.1:12006/mcp` and timeout `120` |

## Notes

- Docker is optional; it does not solve multi-instance spawning by itself.
- Shared daemon + URL transport is the primary OOM mitigation path for Codex.
