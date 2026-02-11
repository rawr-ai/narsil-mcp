#!/usr/bin/env python3
"""
Apply a single daemon config to create/update the narsil-mcp launchd service.

Source of truth:
  ~/.config/narsil-mcp/daemon.toml

This script is intentionally small and dependency-free:
  - uses stdlib `tomllib` (Python 3.11+),
  - invokes `scripts/install-launchd.sh` as the generator for plist/wrapper output,
  - keeps secrets out of the config file (keys live in ~/.config/narsil-mcp/daemon.env).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import tomllib


def _expand_path(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))


def _require(condition: bool, msg: str) -> None:
    if not condition:
        raise ValueError(msg)


def _load_config(path: Path) -> dict:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(data, dict), "Config must be a TOML table at the top level.")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply narsil-mcp launchd daemon from a single TOML config.",
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("NARSIL_DAEMON_CONFIG", "~/.config/narsil-mcp/daemon.toml"),
        help="Path to daemon TOML (default: ~/.config/narsil-mcp/daemon.toml)",
    )
    parser.add_argument(
        "--no-load",
        action="store_true",
        help="Only write plist/wrapper; do not load/restart the launchd service.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the generator command without executing it.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    install_script = repo_root / "scripts" / "install-launchd.sh"
    _require(install_script.exists(), f"Missing script: {install_script}")

    config_path = Path(_expand_path(args.config)).resolve()
    _require(config_path.exists(), f"Daemon config not found: {config_path}")

    cfg = _load_config(config_path)

    label = cfg.get("label", "com.rawr.narsil-mcp-heavy")
    _require(isinstance(label, str) and label.strip(), "label must be a non-empty string.")

    host = cfg.get("host", "127.0.0.1")
    path_arg = cfg.get("path", "/mcp")
    port = cfg.get("port", 12006)
    _require(isinstance(host, str) and host.strip(), "host must be a non-empty string.")
    _require(isinstance(path_arg, str) and path_arg.startswith("/"), "path must be a string starting with '/'.")
    _require(isinstance(port, int) and 1 <= port <= 65535, "port must be an int (1-65535).")

    index_path = cfg.get("index_path", "~/.cache/narsil-mcp")
    _require(isinstance(index_path, str) and index_path.strip(), "index_path must be a non-empty string.")

    wrapper_path = cfg.get("wrapper_path", f"{index_path}/launchd-wrapper.sh")
    plist_path = cfg.get("plist_path", f"~/Library/LaunchAgents/{label}.plist")
    env_file = cfg.get("env_file", "~/.config/narsil-mcp/daemon.env")
    bin_path = cfg.get("bin")

    required_repos = cfg.get("required_repos", [])
    optional_repos = cfg.get("optional_repos", [])
    extra_args = cfg.get("extra_args", [])

    _require(isinstance(required_repos, list) and len(required_repos) > 0, "required_repos must be a non-empty array.")
    _require(isinstance(optional_repos, list), "optional_repos must be an array.")
    _require(isinstance(extra_args, list), "extra_args must be an array.")

    required_expanded = [_expand_path(str(p)) for p in required_repos]
    optional_expanded = [_expand_path(str(p)) for p in optional_repos]

    missing_required = [p for p in required_expanded if not Path(p).exists()]
    if missing_required and not args.dry_run:
        raise ValueError(
            "Missing required repos on disk:\n  - " + "\n  - ".join(missing_required)
        )

    cmd: list[str] = [str(install_script)]
    cmd += ["--label", label]
    cmd += ["--host", str(host)]
    cmd += ["--port", str(port)]
    cmd += ["--path", str(path_arg)]
    cmd += ["--index-path", _expand_path(str(index_path))]
    cmd += ["--wrapper", _expand_path(str(wrapper_path))]
    cmd += ["--plist", _expand_path(str(plist_path))]
    cmd += ["--env-file", _expand_path(str(env_file))]

    if isinstance(bin_path, str) and bin_path.strip():
        cmd += ["--bin", _expand_path(bin_path)]

    for r in required_expanded:
        cmd += ["--repo", r]
    for r in optional_expanded:
        cmd += ["--optional-repo", r]

    for a in extra_args:
        cmd += ["--extra-arg", str(a)]

    if args.no_load:
        cmd += ["--no-load"]

    if args.dry_run:
        print(" ".join(cmd))
        return 0

    subprocess.run(cmd, check=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(1)

