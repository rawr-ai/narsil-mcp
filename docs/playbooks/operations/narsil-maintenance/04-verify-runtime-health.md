# 04 - Verify Runtime Health and Scope

Run this immediately after rollout.

## 1) Launcher Health

```bash
./scripts/launcherctl.py status
```

Expected for each instance: `plist=yes loaded=yes http=up`.

## 2) launchd + Port Checks

```bash
launchctl list | rg 'com\\.rawr\\.narsil-mcp'
lsof -nP -iTCP:12006 -sTCP:LISTEN || true
lsof -nP -iTCP:12007 -sTCP:LISTEN || true
```

(Adjust ports to your configured instances.)

## 3) Process Commandline Check

Confirm each daemon process uses the expected binary path and repo roots.

```bash
ps -axo pid,ppid,command | rg 'narsil-mcp --repos' | rg -v rg
```

## 4) MCP Endpoint Checks

```bash
curl -sS -X POST "http://127.0.0.1:12006/mcp" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

curl -sS -X POST "http://127.0.0.1:12006/mcp" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_repos","arguments":{}}}'
```

Repeat for each instance URL.

## 5) Codex MCP Wiring

Confirm `~/.codex-rawr/config.toml` has one MCP URL entry per daemon instance.
