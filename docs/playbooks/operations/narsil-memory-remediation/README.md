# NARSIL Memory Remediation Workstream

This playbook records the evidence gates for the memory-remediation stack that
followed the 2026-06-28 NARSIL MCP daemon investigation. It is intentionally
sanitized: do not commit raw process command lines, environment files, daemon
logs, API keys, client configs, or local-only paths beyond repo-relative and
documented operational examples.

## Source Order

1. Current repo code and tests.
2. Sanitized investigation artifacts from `/tmp/narsil-memory-investigation-20260628/`.
3. MCP Streamable HTTP session behavior from the current MCP transport spec.
4. Recent NARSIL commits called out by the investigation.

## Baseline Findings

The investigation did not prove a live memory leak in the observed daemons. The
largest daemon was consistent with a large retained working set after hydrating
symbols, files, search indexes, neural data, and call graphs. That classification
is not permanent proof: it only means the sampled windows did not show
post-initialization monotonic growth under flat workload.

Confirmed remediation targets:

- MCP HTTP sessions are unbounded unless clients send `DELETE`.
- Search indexing can append duplicate file documents on watcher update paths.
- Regression coverage needs to prove session lifecycle and search replacement
  behavior without mutating live indexed repos.
- Legacy launcher and client configs can leave stale stdio daemons alongside
  the current launchd HTTP fleet.

Conditional target:

- Lower-memory large-root profiles are allowed only after fixture or runtime
  evidence identifies the dominant memory stock. Do not blindly disable neural
  search, call graphs, hybrid search, or large-root indexing.

## Proof Labels

Use separate labels for each claim:

- `static`: code inspection or diff proves a structural property.
- `unit`: focused unit tests prove local behavior.
- `integration`: tests cover component interactions.
- `runtime-local`: local daemon or fixture measurement proves behavior.
- `operational`: live process/config checks prove deployment state.
- `graphite`: branch is restacked/submitted through Graphite.

Do not claim `memory reduced` from static or unit evidence alone. That claim
requires a controlled fixture or runtime-local measurement.

## Branch Ledger

| Branch | Objective | Required Proof |
| --- | --- | --- |
| `codex/narsil-memory-proof-rails` | Add this sanitized workstream record. | static |
| `codex/narsil-mcp-session-pruning` | [Bound MCP HTTP session retention.](02-mcp-session-pruning.md) | unit, integration |
| `codex/narsil-search-index-replace` | [Replace/remove search docs by file path.](03-search-index-replace.md) | unit, integration |
| `codex/narsil-memory-regression-coverage` | Add recurrence tests and fixture coverage. | unit, integration |
| `codex/narsil-legacy-launcher-cleanup` | Make stale launcher/client artifacts detectable and reversible to clean up. | static, operational |
| `codex/narsil-large-root-profiles` | Conditional opt-in memory profile after proof. | runtime-local |

## Runtime Proof Commands

Use these only against controlled fixtures or explicitly approved live daemons:

```bash
ps -o pid,comm,rss,vsz,%cpu,etime -p <pid>
lsof -nP -p <pid> | awk '{print $5}' | sort | uniq -c
netstat -anv | grep '<port>'
vmmap -summary <pid>
```

For MCP HTTP probes, always preserve and clean up a created session:

```bash
curl -i -sS -X POST http://127.0.0.1:<port>/mcp \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

curl -i -sS -X DELETE http://127.0.0.1:<port>/mcp \
  -H "mcp-session-id: <captured-session-id>"
```

## Review Gate

Every remediation branch needs a fresh review wave:

- Discovery: maps intended behavior and competing causes.
- Design: declares expected behavior before code is used as proof.
- Implementation review: checks scope, compatibility, and regression risk.
- Proof audit: verifies the evidence supports the exact claim.

Accepted P1/P2 findings block closure until repaired or explicitly rejected
with source evidence.
