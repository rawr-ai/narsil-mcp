# Narsil Maintainer Runbooks

This directory is the canonical maintainer workflow for this fork.

Use these runbooks in order when shipping daemon/runtime changes:

1. [01 - Preflight, Scans, and Safety](01-preflight-scans-and-safety.md)
2. [02 - Build and Release Binary](02-build-and-release-binary.md)
3. [03 - Rollout Daemons from launcher.toml](03-rollout-daemons-from-launcher.md)
4. [04 - Verify Runtime Health and Scope](04-verify-runtime-health.md)
5. [05 - Fork Rebase Maintenance](05-fork-rebase-maintenance.md)

## What This Replaces

- Ad-hoc daemon restarts
- Hand-editing generated launchd wrappers
- Mixing old single-daemon and new multi-instance guidance

## Canonical Source of Truth

- Daemon instance config: `~/.config/narsil-mcp/launcher.toml`
- Daemon state snapshot: `~/.config/narsil-mcp/launcher.state.toml`
- Generated outputs (never edit directly):
  - `~/Library/LaunchAgents/<label>.plist`
  - `<index_path>/launchd-wrapper.sh`

## Fast Path (Patch Release)

If no upstream rebase is required:

1. Run 01
2. Run 02
3. Run 03
4. Run 04

If upstream changed and fork sync is needed, run 05 first.
