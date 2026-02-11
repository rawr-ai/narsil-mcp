# Launcher Migration Scratchpad (Keep Updated)

This scratchpad is the working log + checklist for migrating narsil-mcp daemon ops from a single-instance config to a multi-instance launcher config.

Constraints:
- No domain-specific content in repo docs (no CIV/Magic).
- One permanent config defines instances.
- No “patch generated wrapper output” hacks; regenerate from source config.
- Non-interactive commits only.
- Keep fork model: `main` mirrors `upstream/main`; ship from `codex/integration-upstream-main`.

## Plan (From Session)

### Objective
Reintroduce multi-instance daemon management (multiple launchd daemons, one per domain) using a single permanent config file:

- Canonical config: `~/.config/narsil-mcp/launcher.toml`
- Repo example: `configs/launcher.example.toml`
- Tooling: `scripts/launcherctl.py` (stdlib Python; no deps)

### Behavior (launcherctl)
- `apply`: install/update each instance via `scripts/install-launchd.sh` and reconcile removed instances (bootout + delete generated artifacts).
- `status`: show plist exists, launchd running, and HTTP endpoint reachable.
- `restart`: `launchctl kickstart -k gui/$UID/<label>`
- `stop`: `launchctl bootout ...`

### Schema (launcher.toml)
- versioned (`version = 1`)
- defaults (`default_env_file`, `default_host`, `default_path`, `default_bin`, `default_plist_dir`, `default_cache_root`)
- `[[instances]]` with `id`, `label`, `port`, `index_path?`, `repos`, `optional_repos?`, `extra_args?`

### Cleanup strategy
Use a state file in user config dir to know what was previously managed:
- `~/.config/narsil-mcp/launcher.state.toml`

## Execution Checklist

1. Add `docs/notes/launcher-migration-scratchpad.md` (this file) as the first commit.
2. Add `configs/launcher.example.toml`.
3. Add `scripts/launcherctl.py` (`apply/status/restart/stop`).
4. Remove superseded single-daemon config/apply surfaces.
5. Update docs + README:
   - remove stale single-daemon references and make launcher config canonical
   - make launcher config canonical
   - keep examples placeholder-only
6. Ensure `scripts/install-launchd.sh` is compatible (already supports `--optional-repo`; keep it).
7. Run:
   - `cargo fmt --all`
   - `cargo test --features "native,neural" -- --test-threads=1`
8. Non-interactive commits (small logical slices):
   - `docs: add launcher migration scratchpad`
   - `feat: add launcherctl and launcher config`
   - `chore: remove superseded single-daemon surfaces`
   - `docs: update daemon runbooks to launcher`
9. Fast-forward merge into `codex/integration-upstream-main`, push.
10. Remove worktree and delete feature branch.

## Notes / Progress
- [x] Scratchpad committed
- [x] Launcher config + launcherctl implemented
- [x] Docs updated, launcher config is canonical
- [x] Tests green
- [x] Merged + pushed, worktree cleaned
