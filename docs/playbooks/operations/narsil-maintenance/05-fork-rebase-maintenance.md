# 05 - Fork Rebase Maintenance

This is the long-term fork maintenance model for this repository.

## Branch Model

- `main`: exact mirror of `upstream/main` (no fork-only commits)
- `codex/integration-upstream-main`: long-lived shipping branch
- short-lived work slices: `agent-<id>-...` stacked above integration

## Remote Model

- `origin`: fork repository
- `upstream`: upstream repository (fetch-only)

## Integration Procedure

### 1) Refresh Mirror Branch

```bash
git fetch upstream
git checkout main
git reset --hard upstream/main
git push --force-with-lease origin main
```

Before changing the shipping branch, record its tip in a timestamped backup
branch and tag. Never rely on the reflog as the only recovery path.

```bash
git branch backup/codex/integration-upstream-main/<timestamp> codex/integration-upstream-main
git tag backup-narsil-integration-<timestamp> codex/integration-upstream-main
```

### 2) Prove the Upstream Baseline

Create a clean worktree at `upstream/main` and run the complete test suite before
adding fork code. A failure here belongs to upstream or the local toolchain, not
the fork integration.

### 3) Choose Rebase or Semantic Refork

Use a normal rebase only when the fork queue applies without broad conflicts in
shared behavioral code.

When upstream and the fork both changed indexing, persistence, search, watcher,
or transport behavior, rebuild the queue instead:

1. Start a new integration branch at the proven upstream commit.
2. Classify every old fork commit as retained, superseded by upstream, or
   intentionally dropped.
3. Reapply retained capabilities against the upstream design rather than
   selecting whole conflict sides.
4. Keep the result as a small, reviewable patch queue.

Transitional notes, dependency pins that upstream no longer needs, and fixes
already present upstream should not be carried forward.

### 4) Compare and Validate

Use `git range-diff` between the old fork range and the rebuilt queue as an audit
aid. It does not replace semantic review when commits were consolidated.

Run runbooks 01 through 04.

For watcher changes, validation must include a live ignored-output churn test:
the index bytes and modification time should remain stable and the normal-level
log should not grow per raw filesystem event.

### 5) Publish

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
