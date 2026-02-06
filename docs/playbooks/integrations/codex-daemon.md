# Codex Shared Daemon (OOM-Friendly)

Use one long-lived `narsil-mcp` process and connect Codex via `url` transport to avoid one heavy process per session/thread.

## Why This Helps

In stdio mode, each MCP client process launches its own `narsil-mcp` instance. If you run several Codex sessions at once, memory multiplies quickly.

Daemon mode runs one shared engine process and serves MCP over HTTP:

- one index + one memory footprint,
- multiple Codex sessions connect to the same endpoint,
- same tools and behavior as stdio for normal request/response flows.

## 1) Start the daemon

From this repo:

```bash
./scripts/start-daemon.sh \
  --repos /absolute/path/to/repo-a \
  --repos /absolute/path/to/repo-b \
  --git \
  --call-graph
```

Check status:

```bash
./scripts/status-daemon.sh
```

Stop:

```bash
./scripts/stop-daemon.sh
```

List all current-user `narsil-mcp` instances (daemon + stdio):

```bash
./scripts/list-instances.sh
```

Shut down all current-user `narsil-mcp` instances:

```bash
./scripts/shutdown-all.sh
```

Dry-run shutdown (no signals sent):

```bash
./scripts/shutdown-all.sh --dry-run
```

Shut down only matching repo path fragments:

```bash
./scripts/shutdown-all.sh --repo /absolute/path/to/repo-a
```

Default endpoint:

- `http://127.0.0.1:12006/mcp`

## 2) Point Codex to the shared endpoint

In `~/.codex-rawr/config.toml`, prefer URL transport for this server:

```toml
[mcp_servers.narsil-code-intel]
url = "http://127.0.0.1:12006/mcp"
startup_timeout_sec = 30
```

## 3) Use stable repo IDs

`list_repos` now returns stable IDs in this format:

- `<basename>#<short_hash>`

Example:

- `my-api#8f42c1ab`

When two repos share the same basename, bare basename is ambiguous and rejected with candidate IDs.

Supported repo inputs:

- stable `repo_id` (recommended),
- full repo path,
- basename only when unique.

## 4) Memory profile recommendations

For always-on daemon usage, start conservative and add heavy features only when needed:

- Keep: `--persist`
- Add as needed: `--git`, `--call-graph`
- Avoid by default: `--watch`, `--lsp`, `--neural`

Run a separate heavy profile only for deep analysis sessions.

## 5) Auto-start examples

### launchd (macOS)

Create `~/Library/LaunchAgents/com.narsil.mcp.plist` with:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.narsil.mcp</string>
  <key>ProgramArguments</key>
  <array>
    <string>/absolute/path/to/mcp-narsil/scripts/start-daemon.sh</string>
    <string>--repos</string><string>/absolute/path/to/repo-a</string>
    <string>--git</string>
    <string>--call-graph</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
```

Load:

```bash
launchctl load ~/Library/LaunchAgents/com.narsil.mcp.plist
```

### systemd (Linux user service)

`~/.config/systemd/user/narsil-mcp.service`:

```ini
[Unit]
Description=narsil-mcp shared daemon

[Service]
Type=simple
WorkingDirectory=/absolute/path/to/mcp-narsil
ExecStart=/absolute/path/to/mcp-narsil/scripts/start-daemon.sh --repos /absolute/path/to/repo-a --git --call-graph
ExecStop=/absolute/path/to/mcp-narsil/scripts/stop-daemon.sh
Restart=always

[Install]
WantedBy=default.target
```

Enable:

```bash
systemctl --user daemon-reload
systemctl --user enable --now narsil-mcp
```
