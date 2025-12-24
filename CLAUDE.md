# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

narsil-mcp is a Rust MCP (Model Context Protocol) server that provides comprehensive code intelligence capabilities to AI assistants. It indexes codebases using tree-sitter for multi-language parsing and exposes **76 tools** for:
- Symbol search and code navigation
- Multi-mode code search (BM25, TF-IDF, hybrid, neural)
- Call graph analysis
- Git integration (blame, history, hotspots)
- Security scanning (OWASP Top 10, CWE Top 25, secrets, crypto)
- Supply chain analysis (SBOM generation, vulnerability checks, license compliance)
- Static analysis (CFG, DFG, type inference, taint analysis)
- LSP integration
- Remote GitHub repository support

Communication uses JSON-RPC over stdio.

## Build & Development Commands

```bash
# Build release binary (MCP server only)
cargo build --release

# Build with embedded visualization frontend
cargo build --release --features frontend

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- --repos ./path/to/repo

# Format and lint
cargo fmt
cargo clippy

# Test with MCP Inspector
npx @modelcontextprotocol/inspector ./target/release/narsil-mcp --repos ./path/to/repo
```

## CLI Flags

```bash
narsil-mcp \
  --repos ~/project \        # Repository paths to index (can specify multiple)
  --index-path ~/.cache/narsil-mcp \  # Path for persistent index storage
  --git \                    # Enable git blame/history
  --call-graph \             # Enable call graph analysis
  --persist \                # Save index to disk
  --watch \                  # Auto-reindex on file changes
  --lsp \                    # Enable LSP integration (requires language servers)
  --streaming \              # Enable streaming for large results
  --remote \                 # Enable GitHub remote repo support (uses GITHUB_TOKEN)
  --neural \                 # Enable neural embeddings (requires API key)
  --neural-backend api \     # Neural backend: "api" (default) or "onnx"
  --neural-model <model> \   # Embedding model (e.g., "voyage-code-2", "text-embedding-3-small")
  --discover ~/projects \    # Auto-discover repositories in directory
  --reindex \                # Force re-index on startup
  --verbose \                # Debug logging to stderr
  --http \                   # Enable HTTP server for visualization frontend
  --http-port 3000           # HTTP server port (default: 3000)
```

## Architecture

The server follows a pipeline architecture:

```
stdio (JSON-RPC) → McpServer → CodeIntelEngine → LanguageParser (tree-sitter)
                                     ↓
                        DashMap indexes (symbols, files, repos)
                                     ↓
        Optional: LspManager, EmbeddingEngine, NeuralEngine, RemoteRepoManager
```

**Key modules:**
- `mcp.rs` - MCP protocol handler, JSON-RPC routing, tool definitions
- `index.rs` - `CodeIntelEngine`: main indexing engine, file caching, tool implementations
- `parser.rs` - `LanguageParser`: tree-sitter multi-language parsing with symbol query patterns
- `symbols.rs` - `Symbol`, `SymbolKind`: symbol data structures and classification
- `tool_handlers/` - Modular tool handler implementations organized by category
- `search.rs` - BM25 search index
- `embeddings.rs` - TF-IDF similarity search
- `hybrid_search.rs` - Combined BM25 + TF-IDF with RRF ranking
- `neural.rs` - Neural embedding search (Voyage, OpenAI)
- `chunking.rs` - AST-aware code chunking
- `callgraph.rs` - Call graph construction and analysis
- `cfg.rs` - Control flow graph builder
- `dfg.rs` - Data flow analysis
- `type_inference.rs` - Type inference for Python/JS/TS
- `taint.rs` - Taint analysis for security
- `security_rules.rs` - Security vulnerability scanning engine
- `supply_chain.rs` - SBOM and dependency analysis
- `git.rs` - Git integration (blame, history, contributors)
- `lsp.rs` - LSP client for hover, go-to-definition
- `remote.rs` - GitHub API integration for remote repos
- `persist.rs` - Index persistence and file watching
- `incremental.rs` - Incremental indexing with Merkle trees
- `streaming.rs` - Streaming large result sets
- `metrics.rs` - Performance tracking
- `http_server.rs` - HTTP server for visualization frontend
- `tool_handlers/graph.rs` - Graph visualization JSON API for call graphs, imports, symbols

**Data flow:**
1. Repositories are walked using `ignore` crate (respects .gitignore)
2. Files are parsed in parallel using Rayon
3. Tree-sitter queries extract symbols per language
4. Symbols and file contents cached in concurrent `DashMap`s
5. MCP tools query the indexes to serve requests

## Supported Languages (14)

| Language | Extensions | Symbol Types |
|----------|------------|--------------|
| Rust | `.rs` | functions, structs, enums, traits, impls, types, consts, statics, mods |
| Python | `.py`, `.pyi` | functions, classes |
| JavaScript | `.js`, `.jsx`, `.mjs` | functions, classes, methods, arrow functions, variables |
| TypeScript | `.ts` | functions, classes, methods, interfaces, types, enums |
| TSX | `.tsx` | functions, classes, methods, interfaces, types |
| Go | `.go` | functions, methods, types |
| C | `.c`, `.h` | functions, structs, enums, typedefs |
| C++ | `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`, `.hh` | functions, classes, structs, enums, namespaces |
| Java | `.java` | methods, classes, interfaces, enums |
| C# | `.cs` | methods, classes, interfaces, structs, enums, records, delegates, namespaces, properties |
| Bash | `.sh`, `.bash`, `.zsh` | functions, variables |
| Ruby | `.rb`, `.rake`, `.gemspec` | methods, singleton methods, classes, modules |
| Kotlin | `.kt`, `.kts` | functions, classes, objects, interfaces |
| PHP | `.php`, `.phtml` | functions, methods, classes, interfaces, traits |

## MCP Tools (76 total)

**Important:** Tools use short parameter names. Use `repo` (not `repo_path`), `symbol` (not `symbol_name`), `path` (not `file_path`). The `repo` parameter expects the repository name from `list_repos`, not the full path.

### Repository & Files (10 tools)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_repos` | List all indexed repositories | - |
| `get_project_structure` | Get directory tree view | `repo` |
| `get_file` | Get file contents (optional line range) | `repo`, `path` |
| `get_excerpt` | Extract code around specific lines | `repo`, `path`, `lines[]` |
| `reindex` | Trigger re-indexing | - |
| `discover_repos` | Find repos in a directory | `path` |
| `validate_repo` | Check if path is valid repo | `path` |
| `get_index_status` | Show index stats and features | - |
| `get_incremental_status` | Get Merkle tree and change stats | `repo` |
| `get_metrics` | Performance stats and timing | - |

### Symbols (7 tools)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `find_symbols` | Find structs, functions, etc. | `repo` |
| `get_symbol_definition` | Get symbol source with context | `repo`, `symbol` |
| `find_references` | Find all symbol references | `repo`, `symbol` |
| `get_dependencies` | Analyze imports/dependencies | `repo`, `path` |
| `find_symbol_usages` | Find all usages across files | `repo`, `symbol` |
| `get_export_map` | Get exported symbols from file | `repo`, `path` |
| `workspace_symbol_search` | Fuzzy search symbols across workspace | `query` |

### Search (12 tools)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `search_code` | Keyword search with ranking | `query` |
| `semantic_search` | BM25-ranked semantic search | `query` |
| `hybrid_search` | Combined BM25 + TF-IDF with RRF | `query` |
| `neural_search` | Neural embedding search (requires --neural) | `query` |
| `search_chunks` | Search AST-aware code chunks | `query` |
| `find_similar_code` | Find code similar to snippet | `query` |
| `find_similar_to_symbol` | Find code similar to symbol | `repo`, `symbol` |
| `find_semantic_clones` | Find Type-3/4 code clones | `repo`, `path`, `function` |
| `get_embedding_stats` | TF-IDF embedding statistics | - |
| `get_neural_stats` | Neural embedding statistics | - |
| `get_chunk_stats` | Code chunking statistics | `repo` |
| `get_chunks` | Get AST-aware chunks for file | `repo`, `path` |

### Call Graph (6 tools, requires --call-graph)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `get_call_graph` | Get call graph for function | `repo` |
| `get_callers` | Find functions that call a function | `repo`, `function` |
| `get_callees` | Find functions called by a function | `repo`, `function` |
| `find_call_path` | Find path between two functions | `repo`, `from`, `to` |
| `get_complexity` | Get cyclomatic/cognitive complexity | `repo`, `function` |
| `get_function_hotspots` | Find highly connected functions | `repo` |

### Git Integration (9 tools, requires --git)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `get_blame` | Git blame for file | `repo`, `path` |
| `get_file_history` | Commit history for file | `repo`, `path` |
| `get_recent_changes` | Recent commits in repo | `repo` |
| `get_hotspots` | Files with high churn | `repo` |
| `get_contributors` | Repo/file contributors | `repo` |
| `get_commit_diff` | Diff for specific commit | `repo`, `commit` |
| `get_symbol_history` | Commits that changed a symbol | `repo`, `path`, `symbol` |
| `get_branch_info` | Current branch and status | `repo` |
| `get_modified_files` | Working tree changes | `repo` |

### LSP Integration (3 tools, enhanced with --lsp)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `get_hover_info` | Type info and docs at position | `repo`, `path`, `line`, `character` |
| `get_type_info` | Precise type information | `repo`, `path`, `line`, `character` |
| `go_to_definition` | Find definition location | `repo`, `path`, `line`, `character` |

### Remote Repos (3 tools, requires --remote)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `add_remote_repo` | Clone and index GitHub repo | `url` |
| `list_remote_files` | List files via GitHub API | `url` |
| `get_remote_file` | Fetch file via GitHub API | `url`, `path` |

### Security Scanning (9 tools)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `scan_security` | Scan for vulnerabilities using rules engine | `repo` |
| `check_owasp_top10` | Scan for OWASP Top 10 2021 vulnerabilities | `repo` |
| `check_cwe_top25` | Scan for CWE Top 25 weaknesses | `repo` |
| `find_injection_vulnerabilities` | Find SQL, XSS, command, path injection | `repo` |
| `trace_taint` | Trace tainted data flow from source | `repo`, `path`, `line` |
| `get_taint_sources` | List all taint sources (user input, file, network) | `repo` |
| `get_security_summary` | Comprehensive security report | `repo` |
| `explain_vulnerability` | Get detailed explanation for vuln type | `rule_id` or `cwe` |
| `suggest_fix` | Get suggested fix for finding | `repo`, `path`, `line` |

### Supply Chain (4 tools)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `generate_sbom` | Generate CycloneDX/SPDX SBOM | `repo` |
| `check_dependencies` | Check deps for known vulnerabilities (OSV) | `repo` |
| `check_licenses` | Analyze license compliance | `repo` |
| `find_upgrade_path` | Find safe upgrade paths for vulnerable deps | `repo` |

### Code Analysis (11 tools)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `get_control_flow` | Get CFG for function (basic blocks, branches, loops) | `repo`, `path`, `function` |
| `find_dead_code` | Find unreachable code blocks | `repo`, `path` |
| `get_data_flow` | Get DFG showing variable defs and uses | `repo`, `path`, `function` |
| `get_reaching_definitions` | Which assignments reach each point | `repo`, `path`, `function` |
| `find_uninitialized` | Find variables used before initialization | `repo`, `path` |
| `find_dead_stores` | Find assignments that are never read | `repo`, `path` |
| `infer_types` | Infer types for Python/JS/TS functions | `repo`, `path`, `function` |
| `check_type_errors` | Find potential type errors without external checker | `repo`, `path` |
| `get_typed_taint_flow` | Enhanced taint analysis with type info | `repo`, `path`, `source_line` |
| `get_import_graph` | Build and analyze import dependency graph | `repo` |
| `find_circular_imports` | Detect circular import dependencies | `repo` |

### Experimental / AI-Assisted (2 tools)
| Tool | Description | Required Params |
|------|-------------|-----------------|
| `explain_codebase` | Get AI-friendly codebase overview | `repo` |
| `find_implementation` | Find where a feature is implemented | `repo`, `feature` |

## Visual Frontend

**Note:** The `get_code_graph` tool is available via HTTP API only (not MCP), for the visualization frontend.

A React-based visualization frontend is available in `frontend/`:

```bash
# Start the backend with HTTP server
./target/release/narsil-mcp --repos ~/project --call-graph --http --http-port 3000

# In another terminal, run the frontend
cd frontend
npm install
npm run dev
```

The frontend provides:
- Interactive graph visualization using Cytoscape.js
- Multiple view types: call graph, import graph, symbol references, hybrid, control flow
- Depth control and focused exploration (double-click to drill down)
- Complexity metrics overlay with color coding
- Security vulnerability overlay
- File-based clustering
- Node details panel with code excerpts
- Multiple layout algorithms (hierarchical, breadth-first, circle, concentric)

**API Endpoints** (when `--http` is enabled):
- `GET /health` - Server health check
- `GET /tools` - List available tools
- `POST /tools/call` - Execute any MCP tool
- `GET /graph?repo=...&view=call&depth=3` - Get graph visualization data

## Security Rules

Built-in security rulesets in `rules/`:
- `owasp-top10.yaml` - OWASP Top 10 2021 vulnerabilities
- `cwe-top25.yaml` - CWE Top 25 Most Dangerous Weaknesses
- `secrets.yaml` - Hardcoded secrets, API keys, passwords
- `crypto.yaml` - Weak cryptography, insecure random
- `bash.yaml` - Shell-specific security issues

Supported vulnerability types:
- SQL Injection, XSS, Command Injection, Path Traversal
- Broken Authentication, Sensitive Data Exposure
- Security Misconfiguration, Insecure Deserialization
- SSRF, Buffer Overflows, Use-After-Free
- Hardcoded credentials, weak crypto algorithms

## Adding Language Support

To add a new language:
1. Add tree-sitter crate to `Cargo.toml`
2. Add `LanguageConfig` in `parser.rs` with file extensions and symbol query
3. Symbol queries use tree-sitter query syntax to capture `.name` and `.def` nodes

Example:
```rust
LanguageConfig {
    name: "rust".to_string(),
    language: tree_sitter_rust::LANGUAGE.into(),
    extensions: vec!["rs"],
    symbol_query: r#"
        (function_item name: (identifier) @function.name) @function.def
        (struct_item name: (type_identifier) @struct.name) @struct.def
    "#,
},
```

## Environment Variables

- `GITHUB_TOKEN` - GitHub API authentication for remote repos
- `EMBEDDING_API_KEY`, `VOYAGE_API_KEY`, or `OPENAI_API_KEY` - Neural embedding API keys
- `RUST_LOG` - Logging level (debug, info, warn, error)

## Documentation

- `README.md` - User-facing documentation with installation and usage
- `CHANGELOG.md` - Version history and changes
- `docs/archive/` - Historical documentation from development phases
