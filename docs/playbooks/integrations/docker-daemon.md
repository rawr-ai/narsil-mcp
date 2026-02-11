# Optional Docker Daemon Setup

Docker is optional. It can improve isolation and deployment consistency. For Codex integration, the key is running MCP over HTTP (`--mcp-http`) and pointing clients at the daemon via `url`.

## Minimal Dockerfile

```dockerfile
FROM rust:1.87 as builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin narsil-mcp

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/narsil-mcp /usr/local/bin/narsil-mcp
ENTRYPOINT ["narsil-mcp"]
```

## Example run

```bash
docker run --rm \
  -p 127.0.0.1:12006:12006 \
  -v /absolute/path/to/repo-a:/repos/repo-a:ro \
  -v $HOME/.cache/narsil-mcp:/cache/narsil-mcp \
  -e VOYAGE_API_KEY=$VOYAGE_API_KEY \
  narsil-mcp:local \
  --repos /repos/repo-a \
  --index-path /cache/narsil-mcp \
  --persist \
  --mcp-http \
  --mcp-http-host 0.0.0.0 \
  --mcp-http-port 12006 \
  --mcp-http-path /mcp
```

Then point Codex to:

- `http://127.0.0.1:12006/mcp`

## Host vs container data

- Code can stay on host and be bind-mounted (`-v host_repo:/repos/repo:ro`).
- Persisted index should also be bind-mounted to keep warm caches across restarts.
- Keep port bound to localhost (`127.0.0.1`) unless you explicitly need remote access.
