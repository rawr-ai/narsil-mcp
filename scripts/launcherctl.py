#!/usr/bin/env python3
"""
narsil-mcp launcher controller

This manages multiple local launchd daemon instances (one per domain) from a single config:
  ~/.config/narsil-mcp/launcher.toml

Design goals:
- One permanent source of truth for instances
- Durable generation: use scripts/install-launchd.sh as the generator
- Safe cleanup: remove only instances we previously managed (via a state file)
- No external deps (Python 3.11+ for tomllib)
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def expand_path(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))


def load_toml(path: Path) -> dict:
    import tomllib

    return tomllib.loads(path.read_text(encoding="utf-8"))


def toml_quote(s: str) -> str:
    # Minimal TOML string quoting (enough for our state file).
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_state(path: Path, instances: list["ManagedInstance"]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    lines.append("version = 1")
    lines.append("")
    for inst in instances:
        lines.append("[[instances]]")
        lines.append(f"id = {toml_quote(inst.id)}")
        lines.append(f"label = {toml_quote(inst.label)}")
        lines.append(f"plist_path = {toml_quote(inst.plist_path)}")
        lines.append(f"wrapper_path = {toml_quote(inst.wrapper_path)}")
        lines.append(f"index_path = {toml_quote(inst.index_path)}")
        lines.append(f"host = {toml_quote(inst.host)}")
        lines.append(f"port = {inst.port}")
        lines.append(f"path = {toml_quote(inst.path)}")
        lines.append("")
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def load_state(path: Path) -> list["ManagedInstance"]:
    if not path.exists():
        return []
    data = load_toml(path)
    out: list[ManagedInstance] = []
    for raw in data.get("instances", []) or []:
        out.append(
            ManagedInstance(
                id=str(raw["id"]),
                label=str(raw["label"]),
                plist_path=str(raw["plist_path"]),
                wrapper_path=str(raw["wrapper_path"]),
                index_path=str(raw["index_path"]),
                host=str(raw["host"]),
                port=int(raw["port"]),
                path=str(raw["path"]),
            )
        )
    return out


@dataclass(frozen=True)
class InstanceConfig:
    id: str
    label: str
    host: str
    port: int
    path: str
    env_file: str
    bin_path: str | None
    plist_dir: str
    cache_root: str
    index_path: str
    wrapper_path: str
    plist_path: str
    repos: list[str]
    optional_repos: list[str]
    extra_args: list[str]


@dataclass(frozen=True)
class ManagedInstance:
    id: str
    label: str
    plist_path: str
    wrapper_path: str
    index_path: str
    host: str
    port: int
    path: str


def parse_launcher_config(cfg_path: Path) -> list[InstanceConfig]:
    raw = load_toml(cfg_path)

    version = int(raw.get("version", 0))
    if version != 1:
        raise SystemExit(f"Unsupported launcher config version: {version} (expected 1)")

    default_env_file = str(raw.get("default_env_file", "~/.config/narsil-mcp/daemon.env"))
    default_host = str(raw.get("default_host", "127.0.0.1"))
    default_path = str(raw.get("default_path", "/mcp"))
    default_bin = str(raw.get("default_bin", "")).strip() or None
    default_plist_dir = str(raw.get("default_plist_dir", "~/Library/LaunchAgents"))
    default_cache_root = str(raw.get("default_cache_root", "~/.cache/narsil-mcp"))

    instances_raw = raw.get("instances", [])
    if not isinstance(instances_raw, list) or not instances_raw:
        raise SystemExit("launcher.toml must include at least one [[instances]] entry.")

    seen_ids: set[str] = set()
    out: list[InstanceConfig] = []

    for inst in instances_raw:
        inst_id = str(inst["id"])
        if inst_id in seen_ids:
            raise SystemExit(f"Duplicate instance id: {inst_id}")
        seen_ids.add(inst_id)

        label = str(inst.get("label", "")).strip()
        if not label:
            raise SystemExit(f"Instance {inst_id}: missing label")

        host = str(inst.get("host", default_host))
        port = int(inst.get("port"))
        path = str(inst.get("path", default_path))
        env_file = str(inst.get("env_file", default_env_file))
        bin_path = str(inst.get("bin", default_bin or "")).strip() or default_bin
        plist_dir = str(inst.get("plist_dir", default_plist_dir))
        cache_root = str(inst.get("cache_root", default_cache_root))

        index_path = str(inst.get("index_path", "")).strip()
        if not index_path:
            index_path = str(Path(cache_root) / inst_id)

        wrapper_path = str(inst.get("wrapper_path", "")).strip()
        if not wrapper_path:
            wrapper_path = str(Path(index_path) / "launchd-wrapper.sh")

        plist_path = str(inst.get("plist_path", "")).strip()
        if not plist_path:
            plist_path = str(Path(plist_dir) / f"{label}.plist")

        repos = [str(p) for p in (inst.get("repos", []) or [])]
        if not repos:
            raise SystemExit(f"Instance {inst_id}: repos must be a non-empty array")

        optional_repos = [str(p) for p in (inst.get("optional_repos", []) or [])]
        extra_args = [str(a) for a in (inst.get("extra_args", []) or [])]

        out.append(
            InstanceConfig(
                id=inst_id,
                label=label,
                host=host,
                port=port,
                path=path,
                env_file=env_file,
                bin_path=bin_path,
                plist_dir=plist_dir,
                cache_root=cache_root,
                index_path=index_path,
                wrapper_path=wrapper_path,
                plist_path=plist_path,
                repos=repos,
                optional_repos=optional_repos,
                extra_args=extra_args,
            )
        )

    return out


def require_paths_exist(label: str, paths: list[str]) -> None:
    missing = [p for p in paths if not Path(expand_path(p)).exists()]
    if missing:
        joined = "\n".join(f"- {p}" for p in missing)
        raise SystemExit(f"{label}: required repo paths missing:\n{joined}")


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, check=check)


def launchctl_bootout(plist_path: str) -> None:
    uid = str(os.getuid())
    domain = f"gui/{uid}"
    run(["launchctl", "bootout", domain, expand_path(plist_path)], check=False)


def launchctl_kickstart(label: str) -> None:
    uid = str(os.getuid())
    domain = f"gui/{uid}"
    run(["launchctl", "kickstart", "-k", f"{domain}/{label}"], check=False)


def launchctl_is_loaded(label: str) -> bool:
    uid = str(os.getuid())
    domain = f"gui/{uid}"
    cp = subprocess.run(
        ["launchctl", "print", f"{domain}/{label}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cp.returncode == 0


def http_is_up(host: str, port: int, path: str) -> bool:
    url = f"http://{host}:{port}{path}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            _ = resp.read(1)
        return True
    except urllib.error.HTTPError:
        # Any HTTP response means "up".
        return True
    except Exception:
        return False


def apply_instances(repo_root: Path, cfg_path: Path) -> int:
    instances = parse_launcher_config(cfg_path)

    state_path = Path(expand_path("~/.config/narsil-mcp/launcher.state.toml"))
    prev = {i.id: i for i in load_state(state_path)}
    next_ids = {i.id for i in instances}

    # Cleanup instances removed from config.
    removed = [prev[iid] for iid in sorted(prev.keys()) if iid not in next_ids]
    for inst in removed:
        eprint(f"[cleanup] bootout {inst.label}")
        launchctl_bootout(inst.plist_path)
        try:
            Path(expand_path(inst.plist_path)).unlink(missing_ok=True)
        except Exception:
            pass
        # Wrapper is generated output; safe to remove.
        try:
            Path(expand_path(inst.wrapper_path)).unlink(missing_ok=True)
        except Exception:
            pass
        # We do not delete index_path by default (avoid data loss).

    install_script = repo_root / "scripts" / "install-launchd.sh"
    if not install_script.exists():
        raise SystemExit(f"Missing generator script: {install_script}")

    managed: list[ManagedInstance] = []

    for inst in instances:
        require_paths_exist(f"instance {inst.id}", inst.repos)

        cmd = [str(install_script)]
        cmd += ["--label", inst.label]
        cmd += ["--host", inst.host]
        cmd += ["--port", str(inst.port)]
        cmd += ["--path", inst.path]
        cmd += ["--env-file", inst.env_file]
        cmd += ["--index-path", inst.index_path]
        cmd += ["--wrapper", inst.wrapper_path]
        cmd += ["--plist", inst.plist_path]

        if inst.bin_path:
            cmd += ["--bin", inst.bin_path]

        for repo in inst.repos:
            cmd += ["--repo", repo]
        for repo in inst.optional_repos:
            cmd += ["--optional-repo", repo]
        for arg in inst.extra_args:
            cmd += ["--extra-arg", arg]

        eprint(f"[apply] {inst.id} -> {inst.label} ({inst.host}:{inst.port}{inst.path})")
        run(cmd)

        managed.append(
            ManagedInstance(
                id=inst.id,
                label=inst.label,
                plist_path=str(Path(inst.plist_path)),
                wrapper_path=str(Path(inst.wrapper_path)),
                index_path=str(Path(inst.index_path)),
                host=inst.host,
                port=inst.port,
                path=inst.path,
            )
        )

    write_state(state_path, managed)
    return 0


def status_instances(cfg_path: Path) -> int:
    instances = parse_launcher_config(cfg_path)
    for inst in instances:
        plist_exists = Path(expand_path(inst.plist_path)).exists()
        loaded = launchctl_is_loaded(inst.label)
        up = http_is_up(inst.host, inst.port, inst.path) if loaded else False
        print(
            f"{inst.id}: label={inst.label} plist={'yes' if plist_exists else 'no'} "
            f"loaded={'yes' if loaded else 'no'} http={'up' if up else 'down'} "
            f"url=http://{inst.host}:{inst.port}{inst.path}"
        )
    return 0


def stop_instances(cfg_path: Path) -> int:
    instances = parse_launcher_config(cfg_path)
    for inst in instances:
        eprint(f"[stop] {inst.id} -> {inst.label}")
        launchctl_bootout(inst.plist_path)
    return 0


def restart_instances(cfg_path: Path) -> int:
    instances = parse_launcher_config(cfg_path)
    for inst in instances:
        eprint(f"[restart] {inst.id} -> {inst.label}")
        launchctl_kickstart(inst.label)
        time.sleep(0.2)
    return 0


def main(argv: list[str]) -> int:
    repo_root = Path(__file__).resolve().parents[1]

    parser = argparse.ArgumentParser(prog="launcherctl.py")
    parser.add_argument(
        "--config",
        default=os.environ.get("NARSIL_LAUNCHER_CONFIG", "~/.config/narsil-mcp/launcher.toml"),
        help="Path to launcher TOML (default: ~/.config/narsil-mcp/launcher.toml)",
    )

    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("apply")
    sub.add_parser("status")
    sub.add_parser("stop")
    sub.add_parser("restart")

    args = parser.parse_args(argv)
    cfg_path = Path(expand_path(args.config))

    if not cfg_path.exists():
        eprint(f"Missing config: {cfg_path}")
        eprint("Create it by copying: ./configs/launcher.example.toml -> ~/.config/narsil-mcp/launcher.toml")
        return 2

    if args.cmd == "apply":
        return apply_instances(repo_root, cfg_path)
    if args.cmd == "status":
        return status_instances(cfg_path)
    if args.cmd == "stop":
        return stop_instances(cfg_path)
    if args.cmd == "restart":
        return restart_instances(cfg_path)

    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

