# Branch 03: Search Index Replacement

Branch: `codex/narsil-search-index-replace`

## Claim

Incremental file updates no longer append stale BM25 file documents for the same
path. File replacements and deletes now update the lexical search index instead
of leaving old content searchable.

This branch does not claim lower live daemon memory. It removes a proven
append-only growth path; runtime memory impact still requires measurement.

## Design

- Add `SearchIndex::remove_file(path) -> usize`.
- Add `SearchIndex::replace_file(path, content)`.
- Add repo-qualified internal file document ids for engine-owned BM25 file docs,
  while preserving relative `file_path` values in search results.
- Add matching `ConcurrentSearchIndex` wrappers.
- Rebuild derived BM25 postings, document frequencies, and average document
  length after removal so document indices cannot point at stale rows.
- Keep `index_file` append-only for cold indexing and compatibility.
- Use id-qualified replacement for watcher and persisted-sync modify/create
  paths.
- Use id-qualified removal for watcher delete, ignored-file, and targeted
  reindex cleanup paths.
- Keep replacement scoped to the file document; same-path symbol docs are not
  silently dropped by `replace_file`.
- Canonicalize missing deleted paths through the nearest existing parent before
  repo ownership routing, so delete events still resolve after the file is gone.

## Proof

- `unit`: `src/search.rs` tests cover old-term disappearance, delete
  disappearance, preservation of same-path symbol docs, same-relative-path
  multi-repo documents, and rebuilt stats.
- `integration`: `tests/persistence_tests.rs` covers deterministic
  `process_file_changes` modify/delete behavior through `semantic_search`,
  including the two-repo same-relative-path collision case.

## Verification

```bash
cargo test search::tests --lib
cargo test --test persistence_tests process_file_changes
```

## Deferred Notes

This branch does not clean stale TF-IDF embedding docs, neural docs, or the
WASM search path. Those are separate memory surfaces and need their own proof
before changing behavior.
