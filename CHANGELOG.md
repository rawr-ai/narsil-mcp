# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Import graph duplicates** (B2): Deduplicated file paths in `get_import_graph` - each file is now processed only once regardless of symbol count
- **License detection for transitive dependencies** (B3): Added `parse_cargo_lock()` to extract all transitive dependencies with license info; `parse_dependencies()` now prefers Cargo.lock over Cargo.toml
- **Call graph fuzzy function matching** (B5): Applied `find_function()` fuzzy matching in `to_markdown()` and `get_metrics()` - "scan_repository" now correctly finds "CodeIntelEngine::scan_repository"
- Fixed unused import warnings in `src/tool_handlers/mod.rs`

### Added

- **4 new languages**: Bash, Ruby, Kotlin, PHP
  - Bash: `.sh`, `.bash`, `.zsh` - functions, variables
  - Ruby: `.rb`, `.rake`, `.gemspec` - methods, classes, modules
  - Kotlin: `.kt`, `.kts` - functions, classes, objects, interfaces
  - PHP: `.php`, `.phtml` - functions, methods, classes, interfaces, traits
- **Ready-to-use IDE configuration templates** in `/configs`:
  - Claude Desktop (`claude-desktop.json`)
  - Cursor (`.cursor/mcp.json`)
  - VS Code Copilot (`.vscode/mcp.json`)
  - Continue.dev (`continue-config.json`)
- **One-click installer script** (`install.sh`)
  - Auto-detects platform (macOS/Linux, x86_64/arm64)
  - Downloads pre-built binary or builds from source
  - Configures PATH automatically
  - Detects and shows IDE configuration hints
- **Security hardening module** (`security_config.rs`)
  - Secret redaction for tool outputs (API keys, tokens, passwords, private keys)
  - Max file size limits (default 10MB) to prevent DoS
  - Sensitive file detection (`.env`, `.pem`, credentials, etc.)
  - Read-only mode by default
- **DEPENDENCIES.txt** - List of all dependencies for transparency
- **Expanded security rules to all 14 supported languages**:
  - New `rules/bash.yaml` with 5 Bash-specific rules (command injection, temp files, curl TLS, permissions, eval)
  - 3 Rust rules in `cwe-top25.yaml` (unsafe blocks, unwrap/expect, raw pointers)
  - 5 Go rules in `owasp-top10.yaml` (SQL injection, TLS, command injection, path traversal, weak crypto)
  - 5 Java rules (SQL injection, XXE, deserialization, path traversal, LDAP injection)
  - 5 C# rules (SQL injection, deserialization, XSS, path traversal, LDAP injection)
  - 5 Ruby rules (SQL injection, command injection, mass assignment, open redirect, ERB XSS)
  - 5 Kotlin rules (SQL injection, WebView JS, intent handling, hardcoded secrets, insecure random)
  - 6 PHP rules (SQL injection, command injection, file inclusion, unserialize, XSS, path traversal)
  - 2 TypeScript rules (any type usage, non-null assertion)
- **Security test fixtures** for all languages in `test-fixtures/security/`
  - `vulnerable.sh` - Bash vulnerabilities
  - `vulnerable.rs` - Rust vulnerabilities
  - `vulnerable.go` - Go vulnerabilities
  - `vulnerable.java` - Java vulnerabilities
  - `vulnerable.cs` - C# vulnerabilities
  - `vulnerable.rb` - Ruby vulnerabilities
  - `vulnerable.kt` - Kotlin vulnerabilities
  - `vulnerable.php` - PHP vulnerabilities
  - `vulnerable.ts` - TypeScript vulnerabilities

### Changed

- Updated README with competitive comparison table
- Improved documentation structure with badges and better organization
- Total security rules increased from ~74 to 111 (50% increase)

## [1.0.0] - 2025-12-23

### Security

- **Fixed 7 path traversal vulnerabilities** (CWE-22) in the following functions:
  - `trace_taint` - taint analysis endpoint
  - `suggest_fix` - security fix suggestions
  - `get_export_map` - module export analysis
  - `find_semantic_clones` - code clone detection
  - `infer_types` - type inference
  - `check_type_errors` - type error checking
  - `get_typed_taint_flow` - typed taint flow analysis

  All path inputs are now validated using `validate_path()` which performs
  canonicalization and ensures paths stay within the repository root.

### Changed

- Split `neural` feature into two separate features:
  - `neural` - TF-IDF vector search and API-based embeddings (stable)
  - `neural-onnx` - Local ONNX model inference (experimental, requires ort 2.0)
- Updated ort dependency to 2.0.0-rc.10 with new API compatibility

### Fixed

- Fixed compilation issues with ort 2.0.0-rc.10 API changes:
  - Updated `OnnxEmbedder` to use `Mutex<Session>` for thread-safe inference
  - Fixed `try_extract_tensor` return type handling (now returns `(Shape, &[T])`)
  - Removed deprecated `tensor_dimensions()` call
  - Fixed `TensorRef::from_array_view` to take owned view instead of reference
- Fixed usearch save/load to use string paths instead of Path references
- Added missing `neural_config` field to test configurations
- Fixed integration test `test_error_invalid_json` that could hang indefinitely
  - The test now correctly handles JSON-RPC 2.0 spec behavior for malformed input

### Added

- **Test file detection for security scanning**: Added `is_test_file()` function
  that detects test files across languages (Rust, JS/TS, Python, Go, Java)
- **`exclude_tests` parameter for `scan_security`**: Security scans now exclude
  test files by default, reducing false positives from intentional vulnerable
  test fixtures. Set `exclude_tests: false` to include test files.

## [0.2.0] - 2025-12-22

### Added

- Phase 6: Advanced Features
  - Merkle tree-based incremental indexing
  - Cross-language symbol resolution
  - Fuzzy workspace symbol search
  - Import/export graph analysis

- Phase 5: Supply Chain Security
  - SBOM generation (CycloneDX, SPDX formats)
  - Dependency vulnerability checking via OSV database
  - License compliance analysis
  - Upgrade path finder for vulnerable dependencies

- Phase 4: Security Rules Engine
  - OWASP Top 10 2021 scanning
  - CWE Top 25 vulnerability detection
  - Custom YAML security rules support
  - Fix suggestions for common vulnerabilities

- Phase 3: Taint Analysis
  - Source-to-sink data flow tracking
  - SQL injection, XSS, command injection detection
  - Cross-language taint propagation

### Changed

- Improved control flow graph (CFG) analysis
- Enhanced dead code detection
- Better type inference for dynamic languages

## [0.1.0] - 2025-12-20

### Added

- Initial release
- MCP (Model Context Protocol) server implementation
- Multi-language parsing (Rust, Python, JavaScript, TypeScript, Go, C, C++, Java, C#)
- Symbol extraction and search
- Full-text code search with BM25 ranking
- TF-IDF similarity search
- Call graph analysis
- Git integration (blame, history, contributors)
- LSP integration for precise type info
- Remote GitHub repository support
