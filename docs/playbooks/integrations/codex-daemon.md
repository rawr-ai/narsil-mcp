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

In `~/.codex-rawr/config.toml`, use URL transport (not `command`) for `narsil` entries:

```toml
[mcp_servers.narsil-code-intel]
url = "http://127.0.0.1:12006/mcp"
startup_timeout_sec = 120

# Optional compatibility alias: points to same daemon URL
[mcp_servers.narsil-code-intel-heavy]
url = "http://127.0.0.1:12006/mcp"
startup_timeout_sec = 120
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

If you still have any `command = "...narsil-mcp"` blocks in Codex config, Codex can spawn per-session stdio
instances again. Keep Codex-side config URL-only and put heavy flags on the daemon process itself.

## 5) Auto-start examples

### launchd (macOS)

Canonical persistent setup: create `~/Library/LaunchAgents/com.rawr.narsil-mcp-heavy.plist` with:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.rawr.narsil-mcp-heavy</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/zsh</string>
    <string>-lc</string>
    <string>export VOYAGE_API_KEY="$(awk -F'"' '/^VOYAGE_API_KEY/ {print $2; exit}' /Users/you/.codex-rawr/config.toml)"; exec /Users/you/.cargo/bin/narsil-mcp --repos /absolute/path/to/repo-a --index-path /Users/you/.cache/narsil-mcp --persist --git --call-graph --watch --lsp --neural --neural-backend api --neural-model voyage-code-2 --mcp-http --mcp-http-host 127.0.0.1 --mcp-http-port 12006 --mcp-http-path /mcp</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>CODEX_HOME</key><string>/Users/you/.codex-rawr</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/Users/you/.cache/narsil-mcp/launchd.stdout.log</string>
  <key>StandardErrorPath</key><string>/Users/you/.cache/narsil-mcp/launchd.stderr.log</string>
</dict>
</plist>
```

Load/reload:

```bash
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.rawr.narsil-mcp-heavy.plist 2>/dev/null || true
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.rawr.narsil-mcp-heavy.plist
launchctl enable gui/$(id -u)/com.rawr.narsil-mcp-heavy
launchctl kickstart -k gui/$(id -u)/com.rawr.narsil-mcp-heavy
```

Verify:

```bash
./scripts/list-instances.sh
curl -fsS http://127.0.0.1:12006/mcp
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
