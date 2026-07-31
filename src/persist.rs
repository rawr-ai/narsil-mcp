//! Persistent index storage and watch mode for incremental updates
//!
//! Saves index to disk and watches for file changes to update incrementally.

use anyhow::{Context, Result};
#[cfg(feature = "native")]
use notify::{Config, Event, EventKind, PollWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::symbols::Symbol;

/// File metadata for change detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: PathBuf,
    pub content_hash: String,
    pub modified_time: u64,
    pub size: u64,
    pub symbols: Vec<Symbol>,
}

/// Persisted index structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedIndex {
    pub version: u32,
    pub created_at: u64,
    pub updated_at: u64,
    pub repo_root: PathBuf,
    pub files: HashMap<PathBuf, FileMetadata>,
}

impl PersistedIndex {
    const CURRENT_VERSION: u32 = 2;

    pub fn new(repo_root: PathBuf) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            version: Self::CURRENT_VERSION,
            created_at: now,
            updated_at: now,
            repo_root,
            files: HashMap::new(),
        }
    }

    /// Load index from disk
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path).context("Failed to read index file")?;
        let index: Self = postcard::from_bytes(&data).context("Failed to deserialize index")?;

        if index.version != Self::CURRENT_VERSION {
            return Err(anyhow::anyhow!(
                "Index version mismatch: {} != {}",
                index.version,
                Self::CURRENT_VERSION
            ));
        }

        Ok(index)
    }

    /// Save index to disk
    pub fn save(&self, path: &Path) -> Result<()> {
        let data = postcard::to_stdvec(self).context("Failed to serialize index")?;

        // Write to a unique temp file then rename for atomicity.
        // Using a fixed temp path is unsafe if multiple processes share the same index directory.
        let suffix = {
            let pid = std::process::id();
            let ts = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("tmp.{}.{}", pid, ts)
        };
        let temp_path = path.with_extension(suffix);
        std::fs::write(&temp_path, &data).context("Failed to write temp index")?;
        std::fs::rename(&temp_path, path).context("Failed to rename index file")?;

        Ok(())
    }

    /// Check if a file needs re-indexing
    pub fn needs_reindex(&self, path: &Path) -> Result<bool> {
        let metadata = std::fs::metadata(path)?;
        let modified = metadata
            .modified()?
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos();
        let modified: u64 = modified.try_into().unwrap_or(u64::MAX);
        let size = metadata.len();

        if let Some(cached) = self.files.get(path) {
            // Quick check: size and mtime
            if cached.size == size && cached.modified_time == modified {
                return Ok(false);
            }

            // Slower check: content hash
            let hash = hash_file(path)?;
            Ok(hash != cached.content_hash)
        } else {
            Ok(true)
        }
    }

    /// Update file in index
    pub fn update_file(&mut self, path: PathBuf, symbols: Vec<Symbol>) -> Result<()> {
        let metadata = std::fs::metadata(&path)?;
        let hash = hash_file(&path)?;

        self.files.insert(
            path.clone(),
            FileMetadata {
                path,
                content_hash: hash,
                modified_time: metadata
                    .modified()?
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_nanos()
                    .try_into()
                    .unwrap_or(u64::MAX),
                size: metadata.len(),
                symbols,
            },
        );

        self.updated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Ok(())
    }

    /// Remove file from index
    pub fn remove_file(&mut self, path: &Path) {
        self.files.remove(path);
        self.updated_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Get all symbols across all files
    pub fn all_symbols(&self) -> Vec<&Symbol> {
        self.files.values().flat_map(|f| f.symbols.iter()).collect()
    }

    /// Get symbols for a specific file
    pub fn file_symbols(&self, path: &Path) -> Option<&[Symbol]> {
        self.files.get(path).map(|f| f.symbols.as_slice())
    }
}

/// Compute SHA256 hash of file content
fn hash_file(path: &Path) -> Result<String> {
    let content = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Index storage manager
pub struct IndexStore {
    index_dir: PathBuf,
}

impl IndexStore {
    pub fn new(index_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&index_dir)?;
        Ok(Self { index_dir })
    }

    /// Get the index file path for a repository
    pub fn index_path(&self, repo_root: &Path) -> PathBuf {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(repo_root.to_string_lossy().as_bytes());
            format!("{:x}", hasher.finalize())
        };
        self.index_dir.join(format!("{}.idx", &hash[..16]))
    }

    /// Load or create index for a repository
    pub fn load_or_create(&self, repo_root: &Path) -> Result<PersistedIndex> {
        let index_path = self.index_path(repo_root);

        if index_path.exists() {
            match PersistedIndex::load(&index_path) {
                Ok(index) => {
                    info!("Loaded existing index from {:?}", index_path);
                    return Ok(index);
                }
                Err(e) => {
                    warn!("Failed to load index, creating new: {}", e);
                }
            }
        }

        info!("Creating new index for {:?}", repo_root);
        Ok(PersistedIndex::new(repo_root.to_path_buf()))
    }

    /// Save index for a repository
    pub fn save(&self, index: &PersistedIndex) -> Result<()> {
        let index_path = self.index_path(&index.repo_root);
        index.save(&index_path)?;
        info!("Saved index to {:?}", index_path);
        Ok(())
    }

    /// List all cached repositories
    pub fn list_cached(&self) -> Result<Vec<PathBuf>> {
        let mut repos = Vec::new();

        for entry in std::fs::read_dir(&self.index_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "idx").unwrap_or(false) {
                if let Ok(index) = PersistedIndex::load(&path) {
                    repos.push(index.repo_root);
                }
            }
        }

        Ok(repos)
    }
}

/// File watcher for incremental updates (legacy, sync-based polling)
#[cfg(feature = "native")]
pub struct FileWatcher {
    watcher: PollWatcher,
    rx: std::sync::mpsc::Receiver<Result<Event, notify::Error>>,
    watched_paths: Vec<PathBuf>,
}

#[cfg(feature = "native")]
impl FileWatcher {
    pub fn new() -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();

        let watcher = PollWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_millis(500)),
        )?;

        Ok(Self {
            watcher,
            rx,
            watched_paths: Vec::new(),
        })
    }

    /// Start watching a directory
    pub fn watch(&mut self, path: &Path) -> Result<()> {
        self.watcher.watch(path, RecursiveMode::Recursive)?;
        self.watched_paths.push(path.to_path_buf());
        info!("Watching for changes: {:?}", path);
        Ok(())
    }

    /// Stop watching a directory
    pub fn unwatch(&mut self, path: &Path) -> Result<()> {
        self.watcher.unwatch(path)?;
        self.watched_paths.retain(|p| p != path);
        Ok(())
    }

    /// Poll for file changes (non-blocking)
    pub fn poll_changes(&self) -> Vec<FileChange> {
        let mut changes = Vec::new();

        while let Ok(result) = self.rx.try_recv() {
            if let Ok(event) = result {
                for path in event.paths {
                    let change_type = match event.kind {
                        EventKind::Create(_) => ChangeType::Created,
                        EventKind::Modify(_) => ChangeType::Modified,
                        EventKind::Remove(_) => ChangeType::Deleted,
                        _ => continue,
                    };

                    let repo_root = owning_watched_root(&self.watched_paths, &path);
                    changes.extend(source_changes_for_path(&path, change_type, repo_root));
                }
            }
        }

        // Deduplicate
        changes.sort_by(|a, b| a.path.cmp(&b.path));
        changes.dedup_by(|a, b| a.path == b.path);

        changes
    }

    /// Block until changes occur
    pub fn wait_for_changes(&self, timeout: Duration) -> Vec<FileChange> {
        let mut changes = Vec::new();

        if let Ok(Ok(event)) = self.rx.recv_timeout(timeout) {
            for path in event.paths {
                let change_type = match event.kind {
                    EventKind::Create(_) => ChangeType::Created,
                    EventKind::Modify(_) => ChangeType::Modified,
                    EventKind::Remove(_) => ChangeType::Deleted,
                    _ => continue,
                };

                let repo_root = owning_watched_root(&self.watched_paths, &path);
                changes.extend(source_changes_for_path(&path, change_type, repo_root));
            }
        }

        // Drain any additional events
        changes.extend(self.poll_changes());

        changes
    }
}

/// Async file watcher for event-driven incremental updates
#[cfg(feature = "native")]
pub struct AsyncFileWatcher {
    _watcher: PollWatcher,
    watched_paths: Arc<RwLock<Vec<PathBuf>>>,
}

#[cfg(feature = "native")]
impl AsyncFileWatcher {
    /// Create a new async file watcher and return a channel receiver for events
    pub fn new() -> Result<(Self, mpsc::Receiver<Vec<FileChange>>)> {
        let (tx, rx) = mpsc::channel(100);
        let watched_paths = Arc::new(RwLock::new(Vec::<PathBuf>::new()));
        let event_roots = Arc::clone(&watched_paths);

        // Create a channel for the notify watcher
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();

        let watcher = PollWatcher::new(
            move |res| {
                let _ = notify_tx.send(res);
            },
            Config::default().with_poll_interval(Duration::from_millis(500)),
        )?;

        // Spawn a task to process notify events and send batched changes
        tokio::spawn(async move {
            let mut debounce_buffer: HashMap<PathBuf, FileChange> = HashMap::new();
            let debounce_duration = Duration::from_millis(300);
            let mut debounce_timer = tokio::time::interval(debounce_duration);
            debounce_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    // Receive events from notify
                    Some(result) = notify_rx.recv() => {
                        if let Ok(event) = result {
                            for path in event.paths {
                                let change_type = match event.kind {
                                    EventKind::Create(_) => ChangeType::Created,
                                    EventKind::Modify(_) => ChangeType::Modified,
                                    EventKind::Remove(_) => ChangeType::Deleted,
                                    _ => continue,
                                };

                                let roots = event_roots.read();
                                let repo_root = owning_watched_root(&roots, &path);
                                for change in source_changes_for_path(
                                    &path,
                                    change_type.clone(),
                                    repo_root,
                                ) {
                                    // Add to debounce buffer (overwrites previous events for same file)
                                    debounce_buffer.insert(change.path.clone(), change);
                                }
                            }
                        }
                    }
                    // Debounce timer tick - flush buffered changes
                    _ = debounce_timer.tick() => {
                        if !debounce_buffer.is_empty() {
                            let changes: Vec<FileChange> = debounce_buffer.drain().map(|(_, v)| v).collect();
                            if tx.send(changes).await.is_err() {
                                // Receiver dropped, exit task
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok((
            Self {
                _watcher: watcher,
                watched_paths,
            },
            rx,
        ))
    }

    /// Watch a directory for changes
    pub fn watch(&mut self, path: &Path) -> Result<()> {
        self._watcher.watch(path, RecursiveMode::Recursive)?;
        let normalized = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        self.watched_paths.write().push(normalized);
        info!("Async watching for changes: {:?}", path);
        Ok(())
    }

    /// Stop watching a directory
    pub fn unwatch(&mut self, path: &Path) -> Result<()> {
        self._watcher.unwatch(path)?;
        let normalized = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        self.watched_paths.write().retain(|p| p != &normalized);
        Ok(())
    }

    /// Get the list of watched paths
    pub fn watched_paths(&self) -> Vec<PathBuf> {
        self.watched_paths.read().clone()
    }
}

/// A detected file change
#[derive(Debug, Clone)]
pub struct FileChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    Created,
    Modified,
    Deleted,
}

/// Check if a path is a source file we care about
fn is_source_file(path: &Path) -> bool {
    let extensions = [
        "rs", "py", "js", "jsx", "ts", "tsx", "go", "java", "c", "h", "cpp", "hpp", "cc", "cxx",
        "hxx", "swift", "v", "vh", "sv", "svh",
    ];

    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| extensions.contains(&e))
        .unwrap_or(false)
}

/// Convert a notify path into source-file changes.
///
/// Some platforms, especially macOS FSEvents and network/container mounts,
/// can report a directory as modified instead of the exact file. When that
/// happens, scan the reported directory for source files so watch mode does
/// not silently miss the change.
fn source_changes_for_path(
    path: &Path,
    change_type: ChangeType,
    repo_root: Option<&Path>,
) -> Vec<FileChange> {
    if repo_root.is_some_and(|root| path_is_ignored(root, path)) {
        return Vec::new();
    }

    if is_source_file(path) {
        return vec![FileChange {
            path: path.to_path_buf(),
            change_type,
        }];
    }

    if change_type == ChangeType::Deleted || !path.is_dir() {
        return Vec::new();
    }

    let mut changes = Vec::new();
    collect_source_files(path, change_type, &mut changes);
    changes
}

fn owning_watched_root<'a>(roots: &'a [PathBuf], path: &Path) -> Option<&'a Path> {
    roots
        .iter()
        .filter(|root| path.starts_with(root))
        .max_by_key(|root| root.components().count())
        .map(PathBuf::as_path)
}

fn path_is_ignored(repo_root: &Path, path: &Path) -> bool {
    let Ok(relative_path) = path.strip_prefix(repo_root) else {
        return false;
    };
    if relative_path.as_os_str().is_empty() {
        return false;
    }

    let mut builder = ignore::gitignore::GitignoreBuilder::new(repo_root);
    let git_exclude = repo_root.join(".git").join("info").join("exclude");
    if git_exclude.is_file() {
        let _ = builder.add(git_exclude);
    }

    let mut ancestors = Vec::new();
    let mut current = if path.is_dir() {
        Some(path)
    } else {
        path.parent()
    };
    while let Some(dir) = current {
        if !dir.starts_with(repo_root) {
            break;
        }
        ancestors.push(dir);
        if dir == repo_root {
            break;
        }
        current = dir.parent();
    }
    ancestors.reverse();

    for dir in ancestors {
        let ignore_file = dir.join(".gitignore");
        if ignore_file.is_file() {
            let _ = builder.add(ignore_file);
        }
    }

    builder.build().is_ok_and(|matcher| {
        matches!(
            matcher.matched_path_or_any_parents(relative_path, path.is_dir()),
            ignore::Match::Ignore(_)
        )
    })
}

fn collect_source_files(path: &Path, change_type: ChangeType, changes: &mut Vec<FileChange>) {
    let mut builder = ignore::WalkBuilder::new(path);
    builder
        .hidden(true)
        .parents(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .require_git(false);

    for entry in builder.build().flatten() {
        let entry_path = entry.path();
        if entry_path != path
            && entry.file_type().is_some_and(|kind| kind.is_file())
            && is_source_file(entry_path)
        {
            changes.push(FileChange {
                path: entry_path.to_path_buf(),
                change_type: change_type.clone(),
            });
        }
    }
}

/// Incremental indexer that combines persistence and watching
#[cfg(feature = "native")]
pub struct IncrementalIndexer {
    store: IndexStore,
    index: Arc<RwLock<PersistedIndex>>,
    watcher: Option<FileWatcher>,
}

#[cfg(feature = "native")]
impl IncrementalIndexer {
    pub fn new(index_dir: PathBuf, repo_root: &Path) -> Result<Self> {
        let store = IndexStore::new(index_dir)?;
        let index = store.load_or_create(repo_root)?;

        Ok(Self {
            store,
            index: Arc::new(RwLock::new(index)),
            watcher: None,
        })
    }

    /// Enable watch mode
    pub fn enable_watch(&mut self, repo_root: &Path) -> Result<()> {
        let mut watcher = FileWatcher::new()?;
        watcher.watch(repo_root)?;
        self.watcher = Some(watcher);
        Ok(())
    }

    /// Check for and process file changes
    pub fn process_changes<F>(&self, mut reindex_fn: F) -> Result<usize>
    where
        F: FnMut(&Path) -> Result<Vec<Symbol>>,
    {
        let changes = match &self.watcher {
            Some(w) => w.poll_changes(),
            None => return Ok(0),
        };

        if changes.is_empty() {
            return Ok(0);
        }

        let mut index = self.index.write();
        let mut count = 0;

        for change in changes {
            match change.change_type {
                ChangeType::Created | ChangeType::Modified => {
                    debug!("Re-indexing: {:?}", change.path);
                    match reindex_fn(&change.path) {
                        Ok(symbols) => {
                            index.update_file(change.path, symbols)?;
                            count += 1;
                        }
                        Err(e) => {
                            warn!("Failed to index {:?}: {}", change.path, e);
                        }
                    }
                }
                ChangeType::Deleted => {
                    debug!("Removing from index: {:?}", change.path);
                    index.remove_file(&change.path);
                    count += 1;
                }
            }
        }

        if count > 0 {
            self.store.save(&index)?;
        }

        Ok(count)
    }

    /// Get a read reference to the index
    pub fn index(&self) -> Arc<RwLock<PersistedIndex>> {
        Arc::clone(&self.index)
    }

    /// Force save the current index
    pub fn save(&self) -> Result<()> {
        let index = self.index.read();
        self.store.save(&index)
    }

    /// Get files that need re-indexing
    pub fn files_needing_reindex(&self) -> Result<Vec<PathBuf>> {
        let index = self.index.read();
        let mut needs_reindex = Vec::new();

        for path in index.files.keys() {
            if !path.exists() || index.needs_reindex(path)? {
                needs_reindex.push(path.clone());
            }
        }

        Ok(needs_reindex)
    }
}

/// Run the file watcher in background using an async event-driven loop.
///
/// The function exits cleanly when:
/// * The shutdown channel's only `Sender` is dropped (`recv()` returns
///   `Err(Closed)`), or
/// * A `()` value is sent on the shutdown channel.
///
/// **Bug history (issue #26):** the spawn site in `main.rs` used to drop the
/// shutdown sender immediately after creating it, so the receiver here saw
/// `Closed` on the first poll and the watcher exited milliseconds after
/// startup — silently disabling `--watch`. Use `spawn_watch_mode` (below)
/// from new call sites; it returns the sender so the caller cannot forget to
/// keep it alive.
pub async fn run_watch_mode(
    engine: Arc<crate::index::CodeIntelEngine>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    initialization: tokio::sync::oneshot::Receiver<bool>,
) {
    info!("Starting async watch mode background task");

    let (_watcher, mut rx) = match engine.create_async_file_watcher() {
        Some((w, r)) => (w, r),
        None => {
            warn!("Failed to create async file watcher, watch mode disabled");
            return;
        }
    };

    info!("Watch mode waiting for background initialization");
    let Some(pending_changes) =
        wait_for_initialization(initialization, &mut shutdown, &mut rx).await
    else {
        warn!("Watch mode stopped before background initialization completed");
        return;
    };
    info!("Background initialization complete; processing watch events");

    if !pending_changes.is_empty() {
        match engine.process_file_changes(&pending_changes).await {
            Ok(count) if count > 0 => info!("Re-indexed {} file(s)", count),
            Ok(_) => {}
            Err(e) => warn!("Error processing file changes: {}", e),
        }
    }

    loop {
        tokio::select! {
            // Receive batched file change events
            Some(changes) = rx.recv() => {
                if !changes.is_empty() {
                    debug!("Detected {} candidate file change(s)", changes.len());
                    match engine.process_file_changes(&changes).await {
                        Ok(count) => {
                            if count > 0 {
                                info!("Re-indexed {} file(s)", count);
                            }
                        }
                        Err(e) => {
                            warn!("Error processing file changes: {}", e);
                        }
                    }
                }
            }
            // Handle shutdown signal (or all senders dropped)
            _ = shutdown.recv() => {
                info!("Watch mode shutting down");
                break;
            }
        }
    }
}

/// Spawn the watch-mode background task and return the shutdown `Sender`.
///
/// **Callers must hold the returned `Sender` for as long as the watcher
/// should keep running.** Dropping it makes the watcher loop exit on its
/// next poll (this is the cause of issue #26 — the original wiring dropped
/// the sender immediately).
///
/// The spawned task is detached; the returned `Sender` is the only handle
/// needed to keep the watcher alive.
#[must_use = "the returned Sender must be held until the watcher should stop; \
              dropping it immediately exits the watcher (issue #26)"]
pub fn spawn_watch_mode(
    engine: Arc<crate::index::CodeIntelEngine>,
    initialization: tokio::sync::oneshot::Receiver<bool>,
) -> tokio::sync::broadcast::Sender<()> {
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
    tokio::spawn(async move {
        run_watch_mode(engine, shutdown_rx, initialization).await;
    });
    shutdown_tx
}

async fn wait_for_initialization(
    mut initialization: tokio::sync::oneshot::Receiver<bool>,
    shutdown: &mut tokio::sync::broadcast::Receiver<()>,
    changes: &mut mpsc::Receiver<Vec<FileChange>>,
) -> Option<Vec<FileChange>> {
    let mut pending = HashMap::<PathBuf, FileChange>::new();

    loop {
        tokio::select! {
            result = &mut initialization => {
                if !result.unwrap_or(false) {
                    return None;
                }
                return Some(pending.into_values().collect());
            }
            Some(batch) = changes.recv() => {
                for change in batch {
                    pending.insert(change.path.clone(), change);
                }
            }
            _ = shutdown.recv() => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_hash_consistency() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello world").unwrap();

        let hash1 = hash_file(&file).unwrap();
        let hash2 = hash_file(&file).unwrap();
        assert_eq!(hash1, hash2);

        std::fs::write(&file, "hello world!").unwrap();
        let hash3 = hash_file(&file).unwrap();
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_is_source_file() {
        assert!(is_source_file(Path::new("foo.rs")));
        assert!(is_source_file(Path::new("bar.py")));
        assert!(is_source_file(Path::new("src/index.ts")));
        assert!(!is_source_file(Path::new("README.md")));
        assert!(!is_source_file(Path::new("data.json")));
    }

    #[test]
    fn directory_changes_respect_parent_gitignore_rules() {
        let repo = tempdir().unwrap();
        std::fs::write(repo.path().join(".gitignore"), "dist/\n").unwrap();
        let dist = repo.path().join("dist");
        let src = repo.path().join("src");
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(dist.join("ignored.ts"), "export const ignored = true;").unwrap();
        std::fs::write(src.join("included.ts"), "export const included = true;").unwrap();

        assert!(source_changes_for_path(&dist, ChangeType::Modified, Some(repo.path())).is_empty());
        let changes = source_changes_for_path(repo.path(), ChangeType::Modified, Some(repo.path()));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, src.join("included.ts"));
    }

    #[tokio::test]
    async fn initialization_wait_drains_and_coalesces_pending_changes() {
        let (initialization_tx, initialization_rx) = tokio::sync::oneshot::channel();
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel(1);
        let (changes_tx, mut changes_rx) = mpsc::channel(4);

        let wait = tokio::spawn(async move {
            wait_for_initialization(initialization_rx, &mut shutdown_rx, &mut changes_rx).await
        });

        let path = PathBuf::from("src/lib.rs");
        changes_tx
            .send(vec![FileChange {
                path: path.clone(),
                change_type: ChangeType::Modified,
            }])
            .await
            .unwrap();
        changes_tx
            .send(vec![FileChange {
                path: path.clone(),
                change_type: ChangeType::Deleted,
            }])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        initialization_tx.send(true).unwrap();

        let pending = wait.await.unwrap().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].path, path);
        assert_eq!(pending[0].change_type, ChangeType::Deleted);
    }

    #[test]
    fn test_index_store() {
        let dir = tempdir().unwrap();
        let store = IndexStore::new(dir.path().to_path_buf()).unwrap();

        let repo = tempdir().unwrap();
        let index = PersistedIndex::new(repo.path().to_path_buf());

        store.save(&index).unwrap();

        let loaded = store.load_or_create(repo.path()).unwrap();
        assert_eq!(loaded.version, PersistedIndex::CURRENT_VERSION);
    }
}
