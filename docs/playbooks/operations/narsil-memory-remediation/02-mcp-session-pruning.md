# Branch 02: MCP HTTP Session Pruning

Branch: `codex/narsil-mcp-session-pruning`

## Claim

MCP HTTP session retention is now bounded by an idle TTL and a maximum active
session count. This fixes the static unbounded-retention risk identified in the
memory investigation.

This branch does not claim live daemon memory has decreased. Runtime memory
claims require fixture or daemon measurements after deployment.

## Design

- Keep NARSIL's existing stateful MCP HTTP transport behavior.
- Default idle TTL: 1800 seconds.
- Default max active sessions: 512.
- Prune expired sessions opportunistically on `POST`, `GET`, and `DELETE`.
- Return `404` when a client supplies an unknown or expired session ID, so the
  client can reinitialize.
- Serialize the short prune/check/insert admission path so concurrent cold
  starts cannot exceed the configured session cap.
- Keep `DELETE` cleanup for active sessions; later requests carrying deleted,
  unknown, or expired session IDs return `404`.
- Expose only aggregate session diagnostics from `GET`; never expose session
  IDs or request details.

## Proof

- `static`: `src/mcp_http.rs` stores `SessionEntry` values with `last_seen`
  instead of unbounded `Arc<McpServer>` entries.
- `unit`: focused MCP HTTP tests cover session refresh, TTL pruning, max guard,
  DELETE cleanup, and safe diagnostics.
- `integration`: in-process HTTP tests cover real method/status/header behavior
  for session creation, session-cap rejection, DELETE cleanup, GET diagnostics,
  and TTL pruning.

## Verification

```bash
cargo test mcp_http --bin narsil-mcp
```

## Deferred Compatibility Notes

The branch does not implement the full MCP Streamable HTTP transport surface,
such as SSE `GET`, `Accept` negotiation, `MCP-Protocol-Version`, or Origin
validation. Those are adjacent transport-compatibility/security items and should
not be mixed with this memory-retention fix unless separately scoped.
