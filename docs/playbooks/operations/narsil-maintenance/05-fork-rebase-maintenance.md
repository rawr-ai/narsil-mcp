# 05 - Fork Rebase Maintenance

This is the long-term fork maintenance model for this repository.

## Branch Model

- `main`: exact mirror of `upstream/main` (no fork-only commits)
- `codex/integration-upstream-main`: long-lived shipping branch
- short-lived work slices: `agent-<id>-...` stacked above integration

## Remote Model

- `origin`: fork repository
- `upstream`: upstream repository (fetch-only)

## Rebase Procedure

### 1) Refresh Mirror Branch

```bash
git fetch upstream
git checkout main
git reset --hard upstream/main
git push --force-with-lease origin main
```

### 2) Rebase Shipping Branch Onto Mirror

```bash
git checkout codex/integration-upstream-main
git rebase main
```

### 3) Validate

Run runbooks 01 through 04.

### 4) Publish

```bash
git push --force-with-lease origin codex/integration-upstream-main
```

## Graphite Working Rules

- Trunk remains `codex/integration-upstream-main`.
- Use slices for focused changes (`gt create`, `gt modify`).
- In parallel worktree environments, prefer:

```bash
gt sync --no-restack
gt restack --upstack
```

- Submit stacks with:

```bash
gt submit --stack --ai
```

If policy allows immediate integration and checks are green, merge stack branches into trunk.
