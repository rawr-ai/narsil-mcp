# Codex Shared Daemon (Single Instance)

Use one long-lived `narsil-mcp` daemon and connect Codex via URL transport, so new Codex sessions do not spawn new heavy stdio servers.

## Why This Helps

In stdio mode, each MCP client launches its own `narsil-mcp` instance. With multiple Codex threads/sessions, memory usage multiplies.

In URL mode (`--mcp-http`), Codex connects to a shared daemon:

- one index + one memory footprint,
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

### 2) Create daemon config (single source of truth)

Copy:

- `./configs/daemon.example.toml`

To:

- `~/.config/narsil-mcp/daemon.toml`

Then edit `required_repos` and (optionally) `optional_repos`.

### 3) Apply config (install/update launchd)

```bash
./scripts/apply-daemon-config.py
```

This is the durable configuration layer:

- reads `~/.config/narsil-mcp/daemon.toml`,
- generates plist + wrapper via `./scripts/install-launchd.sh`,
- (re)loads the launchd service by default.

Generated outputs (do not hand-edit):

- `~/Library/LaunchAgents/<label>.plist`
- `<index_path>/launchd-wrapper.sh`

If you need behavior changes, change either:

- your `daemon.toml`, or
- the generator (`scripts/install-launchd.sh`),

then rerun `apply-daemon-config.py`.

### 4) Restart + validate

```bash
./scripts/restart-daemon.sh
./scripts/doctor-daemon.sh
```

## Codex Config Contract (`~/.codex-rawr/config.toml`)

Use a URL-only entry:

```toml
[mcp_servers.narsil-code-intel]
url = "http://127.0.0.1:12006/mcp"
startup_timeout_sec = 120
```

Do not set `command = "...narsil-mcp"` for this server.
That re-enables per-session stdio spawning and can reintroduce OOM pressure.

## Why TOML + Python (and not JSON/YAML or Bun/TS)

This repo aims for “works on a fresh machine” daemon ops:

- **TOML**: human-editable, commentable, and consistent with other config surfaces (for example, `config.toml`-style tools).
- **Python**: no external deps; `tomllib` is stdlib in Python 3.11+, so applying the config does not require `npm/bun install` or a build step.

