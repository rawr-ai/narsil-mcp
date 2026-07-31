# Codex Shared Daemons (Per Domain)

Run one long-lived `narsil-mcp` daemon **per domain** (project/domain boundary), and connect Codex via URL transport. This keeps neural search results isolated per domain while avoiding per-session stdio spawning.

## Why This Helps

In stdio mode, each MCP client launches its own `narsil-mcp` instance. With multiple Codex threads/sessions, memory usage multiplies.

In URL mode (`--mcp-http`), Codex connects to a shared daemon:

- one index + one memory footprint per domain,
- many Codex sessions connect to the same endpoint,
- same tools and behavior (request/response MCP).

Important credential rule:

- Codex URL transport does **not** inject per-server env vars into the daemon process.
- Neural API keys must be available in the daemon environment.
- Canonical location: `~/.config/narsil-mcp/daemon.env`.

## Canonical Runbook (macOS launchd)

### 1) Create daemon env file (once)

```bash
./scripts/setup-daemon-env.sh --provider voyage --key 'pa-...'
```

This writes:

- `~/.config/narsil-mcp/daemon.env` (mode `600`)

### 2) Create launcher config (single source of truth)

Copy:

- `./configs/launcher.example.toml`

To:

- `~/.config/narsil-mcp/launcher.toml`

Then define one `[[instances]]` per domain. Each instance can include multiple `repos` and `optional_repos`.

### 3) Apply config (install/update all instances)

```bash
./scripts/launcherctl.py apply
```

This is the durable configuration layer:

- reads `~/.config/narsil-mcp/launcher.toml`,
- generates plist + wrapper via `./scripts/install-launchd.sh` for each instance,
- (re)loads each launchd service by default,
- removes instances that were previously managed but are no longer present in `launcher.toml`.

Generated outputs (do not hand-edit):

- `~/Library/LaunchAgents/<label>.plist`
- `<index_path>/launchd-wrapper.sh`

If you need behavior changes, change either:

- your `launcher.toml`, or
- the generator (`scripts/install-launchd.sh`),

then rerun `launcherctl.py apply`.

### 4) Restart + validate

```bash
./scripts/launcherctl.py restart
./scripts/launcherctl.py status
```

## Codex Config Contract (`~/.codex-rawr/config.toml`)

Use one URL-only entry **per domain**:

```toml
[mcp_servers.narsil-domain-a]
url = "http://127.0.0.1:12006/mcp"
startup_timeout_sec = 120

[mcp_servers.narsil-domain-b]
url = "http://127.0.0.1:12007/mcp"
startup_timeout_sec = 120
```

Do not set `command = "...narsil-mcp"` for this server.
That re-enables per-session stdio spawning and can reintroduce OOM pressure.

## Why TOML + Python (and not JSON/YAML or Bun/TS)

This repo aims for “works on a fresh machine” daemon ops:

- **TOML**: human-editable, commentable, and consistent with other config surfaces (for example, `config.toml`-style tools).
- **Python**: no external deps; `tomllib` is stdlib in Python 3.11+, so applying the config does not require `npm/bun install` or a build step.
