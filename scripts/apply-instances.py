#!/usr/bin/env python3
"""
Apply a single "instances config" to create/update multiple narsil-mcp launchd daemons.

This is the durable "single config" layer:
  - One TOML file describes desired daemons + indexed roots.
  - This script idempotently (re)generates launchd plists/wrappers by invoking install-launchd.sh.

Design goals:
  - No secrets in config (keys live in ~/.config/narsil-mcp/daemon.env).
  - Multi-daemon safe (does not assume exactly one daemon exists).
  - Optional roots are allowed (missing directories are OK).
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
    parser = argparse.ArgumentParser(description="Apply narsil-mcp launchd daemon instances from a TOML config.")
    parser.add_argument(
        "--config",
        default=os.environ.get("NARSIL_DAEMON_INSTANCES_CONFIG", "~/.config/narsil-mcp/instances.toml"),
        help="Path to instances TOML (default: ~/.config/narsil-mcp/instances.toml)",
    )
    parser.add_argument(
        "--no-load",
        action="store_true",
        help="Only write plist/wrapper; do not load/restart launchd services.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands that would run, without executing them.",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    install_script = repo_root / "scripts" / "install-launchd.sh"
    _require(install_script.exists(), f"Missing script: {install_script}")

    config_path = Path(_expand_path(args.config)).resolve()
    _require(config_path.exists(), f"Instances config not found: {config_path}")

    cfg = _load_config(config_path)
    instances = cfg.get("instances")
    _require(isinstance(instances, list) and len(instances) > 0, "Config must contain [[instances]] entries.")

    for idx, inst in enumerate(instances, start=1):
        _require(isinstance(inst, dict), f"instances[{idx}] must be a table.")

        label = inst.get("label")
        _require(isinstance(label, str) and label.strip(), f"instances[{idx}].label is required.")

        port = inst.get("port")
        _require(isinstance(port, int) and 1 <= port <= 65535, f"instances[{idx}].port must be an int 1-65535.")

        host = inst.get("host", "127.0.0.1")
        path_arg = inst.get("path", "/mcp")
        index_path = inst.get("index_path", f"~/.cache/narsil-mcp-{label}")
        wrapper_path = inst.get("wrapper_path", f"{index_path}/launchd-wrapper.sh")
        plist_path = inst.get("plist_path", f"~/Library/LaunchAgents/{label}.plist")
        env_file = inst.get("env_file", "~/.config/narsil-mcp/daemon.env")
        bin_path = inst.get("bin")
        extra_args = inst.get("extra_args", [])

        repos = inst.get("repos", [])
        optional_repos = inst.get("optional_repos", [])
        _require(isinstance(repos, list) and len(repos) > 0, f"instances[{idx}].repos must be a non-empty array.")
        _require(isinstance(optional_repos, list), f"instances[{idx}].optional_repos must be an array.")
        _require(isinstance(extra_args, list), f"instances[{idx}].extra_args must be an array.")

        repos_expanded = [_expand_path(str(p)) for p in repos]
        optional_expanded = [_expand_path(str(p)) for p in optional_repos]

        # Required repos must exist; optional repos are allowed to be missing.
        # In --dry-run mode we allow missing repos so example configs can be previewed.
        missing_required = [p for p in repos_expanded if not Path(p).exists()]
        if missing_required and not args.dry_run:
            raise ValueError(
                f"instances[{idx}] missing required repos on disk:\n  - " + "\n  - ".join(missing_required)
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

        for r in repos_expanded:
            cmd += ["--repo", r]
        for r in optional_expanded:
            cmd += ["--repo", r]

        for a in extra_args:
            cmd += ["--extra-arg", str(a)]

        if args.no_load:
            cmd += ["--no-load"]

        print(f"[{idx}/{len(instances)}] apply {label} -> http://{host}:{port}{path_arg}")
        if args.dry_run:
            print("  " + " ".join(cmd))
            continue

        subprocess.run(cmd, check=True)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(1)
