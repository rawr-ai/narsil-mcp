# 01 - Preflight, Scans, and Safety

Use this before any build/release/rebase step.

## Preconditions

- You are in `/Users/mateicanavra/Documents/.nosync/DEV/mcp-servers/mcp-narsil`.
- Graphite trunk is `codex/integration-upstream-main`.
- You have a clean worktree.

## Repo + Graphite Sanity

```bash
git status --short
git branch --show-current
gt ls
git remote -v
```

Expected:

- no unstaged/staged changes
- trunk branch visible as `codex/integration-upstream-main`
- `origin` = fork, `upstream` = source project

## Single-Runner Safety

Never run multiple release builds in parallel.

```bash
ps -axo pid,ppid,args | rg 'cargo install --path|cargo build --release|rustc .*narsil_mcp|rust-lld' | rg -v rg
```

If anything is running, wait or terminate stale jobs before continuing.

## Required Quality Gates

```bash
cargo fmt --all -- --check
cargo test --features "native,neural" -- --test-threads=1
```

## Optional Heavier Gate

Use for high-risk releases or after major dependency churn.

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Daemon Snapshot (Before Changes)

```bash
./scripts/launcherctl.py status
launchctl list | rg 'com\\.rawr\\.narsil-mcp' || true
```

Save this output in your release notes / PR body.
