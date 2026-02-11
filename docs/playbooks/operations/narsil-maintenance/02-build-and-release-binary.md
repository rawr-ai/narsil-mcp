# 02 - Build and Release Binary

This runbook builds the daemon binary and prepares it for launcher rollout.

## 1) Stop Managed Daemons

Stop all configured instances first to avoid binary replacement races.

```bash
./scripts/launcherctl.py stop
```

## 2) Build Release Binary

```bash
cargo build --release
./target/release/narsil-mcp --version
```

## 3) Ensure launcher.toml Points to the Built Binary

`launcher.toml` must define `default_bin` (or per-instance `bin`) pointing to the intended binary.

Recommended:

```toml
default_bin = "/Users/<you>/Documents/.nosync/DEV/mcp-servers/mcp-narsil/target/release/narsil-mcp"
```

## 4) Optional Global CLI Install

Only if you need `narsil-mcp` on global PATH outside launcher-managed daemons:

```bash
cargo install --path . --force
narsil-mcp --version
```

Do not run this in parallel with other cargo builds.
