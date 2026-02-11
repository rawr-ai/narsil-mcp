# 03 - Rollout Daemons from launcher.toml

This is the canonical rollout path for one or more domain daemons.

## 1) Validate launcher.toml

```bash
ls -la ~/.config/narsil-mcp/launcher.toml
```

Strong recommendation: use absolute paths for `default_bin`, `default_plist_dir`, `default_cache_root`, `env_file`, `index_path`, `wrapper_path`, `plist_path`, and repo roots.

## 2) Apply Configuration

```bash
./scripts/launcherctl.py apply
```

`apply` performs all daemon install/update operations:

- generates launchd plist and wrapper per instance via `install-launchd.sh`
- bootstraps + restarts each service
- reconciles removed instances via `launcher.state.toml`

## 3) Restart (Optional)

```bash
./scripts/launcherctl.py restart
```

## 4) Important Invariants

- `optional_repos` may be empty.
- Wrapper/plist are generated outputs; never hand-edit them.
- Modify only:
  - `~/.config/narsil-mcp/launcher.toml`
  - `scripts/install-launchd.sh` (generator behavior)
