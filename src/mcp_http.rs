use anyhow::Result;
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use dashmap::DashMap;
use parking_lot::Mutex;
use serde_json::json;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::index::CodeIntelEngine;
use crate::mcp::McpServer;

const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";
const DEFAULT_SESSION_IDLE_TTL_SECONDS: u64 = 30 * 60;
const DEFAULT_MAX_SESSIONS: usize = 512;

#[derive(Clone, Debug)]
pub struct McpHttpSessionConfig {
    pub idle_ttl: Duration,
    pub max_sessions: usize,
}

impl Default for McpHttpSessionConfig {
    fn default() -> Self {
        Self {
            idle_ttl: Duration::from_secs(DEFAULT_SESSION_IDLE_TTL_SECONDS),
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }
}

impl McpHttpSessionConfig {
    pub fn new(idle_ttl_seconds: u64, max_sessions: usize) -> Self {
        Self {
            idle_ttl: Duration::from_secs(idle_ttl_seconds),
            max_sessions: max_sessions.max(1),
        }
    }
}

struct SessionEntry {
    server: Arc<McpServer>,
    created_at: Instant,
    last_seen: Instant,
}

impl SessionEntry {
    fn new(server: Arc<McpServer>, now: Instant) -> Self {
        Self {
            server,
            created_at: now,
            last_seen: now,
        }
    }

    fn is_expired(&self, now: Instant, idle_ttl: Duration) -> bool {
        now.duration_since(self.last_seen) >= idle_ttl
    }
}

#[derive(Clone)]
struct McpHttpState {
    engine: Arc<CodeIntelEngine>,
    sessions: Arc<DashMap<String, SessionEntry>>,
    session_lock: Arc<Mutex<()>>,
    preset_override: Option<String>,
    session_config: McpHttpSessionConfig,
    pruned_sessions: Arc<AtomicU64>,
}

pub struct McpHttpServer {
    engine: Arc<CodeIntelEngine>,
    host: String,
    port: u16,
    path: String,
    preset_override: Option<String>,
    session_config: McpHttpSessionConfig,
}

impl McpHttpServer {
    pub fn new(
        engine: Arc<CodeIntelEngine>,
        host: String,
        port: u16,
        path: String,
        preset_override: Option<String>,
        session_config: McpHttpSessionConfig,
    ) -> Self {
        Self {
            engine,
            host,
            port,
            path,
            preset_override,
            session_config,
        }
    }

    pub async fn run(self) -> Result<()> {
        let normalized_path = normalize_path(&self.path);
        let state = McpHttpState {
            engine: Arc::clone(&self.engine),
            sessions: Arc::new(DashMap::new()),
            session_lock: Arc::new(Mutex::new(())),
            preset_override: self.preset_override,
            session_config: self.session_config,
            pruned_sessions: Arc::new(AtomicU64::new(0)),
        };

        let app = build_router(&normalized_path, state);

        let addr = format!("{}:{}", self.host, self.port);
        info!(
            "MCP HTTP server starting on http://{}{}",
            addr, normalized_path
        );
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

fn build_router(normalized_path: &str, state: McpHttpState) -> Router {
    Router::new()
        .route(
            normalized_path,
            post(handle_mcp_post)
                .get(handle_mcp_get)
                .delete(handle_mcp_delete),
        )
        .with_state(state)
}

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

fn session_id_from_headers(headers: &HeaderMap) -> Result<Option<String>, String> {
    match headers.get(MCP_SESSION_ID_HEADER) {
        Some(value) => {
            let session_id = value
                .to_str()
                .map_err(|_| format!("Invalid {} header", MCP_SESSION_ID_HEADER))?;
            validate_session_id(session_id)?;
            Ok(Some(session_id.to_string()))
        }
        None => Ok(None),
    }
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    if session_id.is_empty() || session_id.len() > 128 {
        return Err(format!("Invalid {} header", MCP_SESSION_ID_HEADER));
    }

    if !session_id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(format!("Invalid {} header", MCP_SESSION_ID_HEADER));
    }

    Ok(())
}

fn attach_session_header(
    mut response: axum::response::Response,
    session_id: &str,
) -> axum::response::Response {
    if let Ok(value) = HeaderValue::from_str(session_id) {
        response.headers_mut().insert(MCP_SESSION_ID_HEADER, value);
    }
    response
}

fn bad_session_response(message: String) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": message
        })),
    )
        .into_response()
}

fn prune_idle_sessions(state: &McpHttpState, now: Instant) -> usize {
    let before = state.sessions.len();
    let idle_ttl = state.session_config.idle_ttl;
    state
        .sessions
        .retain(|_, entry| !entry.is_expired(now, idle_ttl));
    let removed = before.saturating_sub(state.sessions.len());
    if removed > 0 {
        state
            .pruned_sessions
            .fetch_add(removed as u64, Ordering::Relaxed);
    }
    removed
}

enum SessionLookup {
    Ready(Arc<McpServer>),
    Expired,
    Full,
}

enum SessionPresence {
    Active,
    UnknownOrExpired,
}

fn session_server(
    state: &McpHttpState,
    session_id: &str,
    explicit_session_id: bool,
    now: Instant,
) -> SessionLookup {
    let _session_guard = state.session_lock.lock();
    prune_idle_sessions(state, now);

    if let Some(mut entry) = state.sessions.get_mut(session_id) {
        if entry.is_expired(now, state.session_config.idle_ttl) {
            drop(entry);
            state.sessions.remove(session_id);
            state.pruned_sessions.fetch_add(1, Ordering::Relaxed);
            return SessionLookup::Expired;
        }

        entry.last_seen = now;
        return SessionLookup::Ready(Arc::clone(&entry.server));
    }

    if explicit_session_id {
        return SessionLookup::Expired;
    }

    if state.sessions.len() >= state.session_config.max_sessions {
        return SessionLookup::Full;
    }

    let server = Arc::new(McpServer::from_arc(
        Arc::clone(&state.engine),
        state.preset_override.clone(),
    ));
    state.sessions.insert(
        session_id.to_string(),
        SessionEntry::new(Arc::clone(&server), now),
    );
    SessionLookup::Ready(server)
}

fn touch_existing_session(state: &McpHttpState, session_id: &str, now: Instant) -> SessionPresence {
    let _session_guard = state.session_lock.lock();
    prune_idle_sessions(state, now);

    if let Some(mut entry) = state.sessions.get_mut(session_id) {
        if entry.is_expired(now, state.session_config.idle_ttl) {
            drop(entry);
            state.sessions.remove(session_id);
            state.pruned_sessions.fetch_add(1, Ordering::Relaxed);
            return SessionPresence::UnknownOrExpired;
        }

        entry.last_seen = now;
        return SessionPresence::Active;
    }

    SessionPresence::UnknownOrExpired
}

async fn handle_mcp_post(
    State(state): State<McpHttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let explicit_session_id = match session_id_from_headers(&headers) {
        Ok(session_id) => session_id,
        Err(message) => return bad_session_response(message),
    };
    let session_id = explicit_session_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let server = match session_server(
        &state,
        &session_id,
        explicit_session_id.is_some(),
        Instant::now(),
    ) {
        SessionLookup::Ready(server) => server,
        SessionLookup::Expired => {
            return attach_session_header(StatusCode::NOT_FOUND.into_response(), &session_id);
        }
        SessionLookup::Full => {
            let response = (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "error": "MCP HTTP session limit reached"
                })),
            )
                .into_response();
            return response;
        }
    };

    let payload = match std::str::from_utf8(&body) {
        Ok(p) => p,
        Err(e) => {
            let response = (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32700, "message": format!("Invalid UTF-8 payload: {}", e) },
                    "id": null
                })),
            )
                .into_response();
            return attach_session_header(response, &session_id);
        }
    };

    match server.handle_jsonrpc(payload).await {
        Ok(Some(response_body)) => {
            let mut response = Json(response_body).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            attach_session_header(response, &session_id)
        }
        Ok(None) => attach_session_header(StatusCode::ACCEPTED.into_response(), &session_id),
        Err(e) => {
            warn!("MCP HTTP request failed for session {}: {}", session_id, e);
            let response = (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "jsonrpc": "2.0",
                    "error": { "code": -32000, "message": e.to_string() },
                    "id": null
                })),
            )
                .into_response();
            attach_session_header(response, &session_id)
        }
    }
}

async fn handle_mcp_get(
    State(state): State<McpHttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let session_id = match session_id_from_headers(&headers) {
        Ok(Some(session_id)) => {
            if matches!(
                touch_existing_session(&state, &session_id, Instant::now()),
                SessionPresence::UnknownOrExpired
            ) {
                return attach_session_header(StatusCode::NOT_FOUND.into_response(), &session_id);
            }
            Some(session_id)
        }
        Ok(None) => None,
        Err(message) => return bad_session_response(message),
    };
    prune_idle_sessions(&state, Instant::now());
    let response = Json(json!({
        "name": "narsil-mcp",
        "status": "ok",
        "transport": "http",
        "message": "POST JSON-RPC requests to this endpoint",
        "sessions": {
            "active": state.sessions.len(),
            "max": state.session_config.max_sessions,
            "idle_ttl_seconds": state.session_config.idle_ttl.as_secs(),
            "pruned": state.pruned_sessions.load(Ordering::Relaxed)
        }
    }))
    .into_response();
    match session_id {
        Some(session_id) => attach_session_header(response, &session_id),
        None => response,
    }
}

async fn handle_mcp_delete(
    State(state): State<McpHttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    prune_idle_sessions(&state, Instant::now());
    let session_id = match session_id_from_headers(&headers) {
        Ok(session_id) => session_id,
        Err(message) => return bad_session_response(message),
    };

    match session_id {
        Some(id) => {
            if state.sessions.remove(&id).is_some() {
                let response = StatusCode::NO_CONTENT.into_response();
                attach_session_header(response, &id)
            } else {
                attach_session_header(StatusCode::NOT_FOUND.into_response(), &id)
            }
        }
        None => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Missing {} header", MCP_SESSION_ID_HEADER)
            })),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{CodeIntelEngine, EngineOptions};
    use axum::body::to_bytes;
    use axum::http::HeaderMap;
    use tempfile::TempDir;

    async fn test_state(idle_ttl_seconds: u64, max_sessions: usize) -> (McpHttpState, TempDir) {
        let index_dir = TempDir::new().expect("failed to create temp index");
        let engine = CodeIntelEngine::with_options(
            index_dir.path().to_path_buf(),
            Vec::new(),
            EngineOptions {
                cache_enabled: false,
                ..EngineOptions::default()
            },
        )
        .await
        .expect("failed to create engine");

        (
            McpHttpState {
                engine: Arc::new(engine),
                sessions: Arc::new(DashMap::new()),
                session_lock: Arc::new(Mutex::new(())),
                preset_override: None,
                session_config: McpHttpSessionConfig::new(idle_ttl_seconds, max_sessions),
                pruned_sessions: Arc::new(AtomicU64::new(0)),
            },
            index_dir,
        )
    }

    #[test]
    fn rejects_invalid_session_ids() {
        assert!(validate_session_id("").is_err());
        assert!(validate_session_id("contains space").is_err());
        assert!(validate_session_id(&"a".repeat(129)).is_err());
        assert!(validate_session_id("abc-123_XYZ").is_ok());
    }

    #[tokio::test]
    async fn creates_and_refreshes_session() {
        let (state, _index_dir) = test_state(1800, 2).await;
        let now = Instant::now();

        let first = session_server(&state, "session-1", false, now);
        assert!(matches!(first, SessionLookup::Ready(_)));
        assert_eq!(state.sessions.len(), 1);

        let original_created_at = state.sessions.get("session-1").unwrap().created_at;
        let later = now + Duration::from_secs(5);
        let second = session_server(&state, "session-1", true, later);
        assert!(matches!(second, SessionLookup::Ready(_)));

        let entry = state.sessions.get("session-1").unwrap();
        assert_eq!(entry.created_at, original_created_at);
        assert_eq!(entry.last_seen, later);
    }

    #[tokio::test]
    async fn expired_known_session_is_removed_and_not_recreated() {
        let (state, _index_dir) = test_state(1, 2).await;
        let now = Instant::now();

        assert!(matches!(
            session_server(&state, "session-1", false, now),
            SessionLookup::Ready(_)
        ));

        let expired = session_server(&state, "session-1", true, now + Duration::from_secs(2));
        assert!(matches!(expired, SessionLookup::Expired));
        assert_eq!(state.sessions.len(), 0);
        assert_eq!(state.pruned_sessions.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn max_session_guard_blocks_unbounded_growth() {
        let (state, _index_dir) = test_state(1800, 1).await;
        let now = Instant::now();

        assert!(matches!(
            session_server(&state, "session-1", false, now),
            SessionLookup::Ready(_)
        ));
        assert!(matches!(
            session_server(&state, "session-2", false, now),
            SessionLookup::Full
        ));
        assert_eq!(state.sessions.len(), 1);
    }

    #[tokio::test]
    async fn max_session_guard_holds_under_concurrent_cold_starts() {
        let (state, _index_dir) = test_state(1800, 1).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(12));
        let mut handles = Vec::new();

        for idx in 0..12 {
            let state = state.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                session_server(&state, &format!("session-{idx}"), false, Instant::now())
            }));
        }

        let mut ready = 0;
        let mut full = 0;
        for handle in handles {
            match handle.await.expect("session task panicked") {
                SessionLookup::Ready(_) => ready += 1,
                SessionLookup::Full => full += 1,
                SessionLookup::Expired => panic!("new sessions should not be expired"),
            }
        }

        assert_eq!(ready, 1);
        assert_eq!(full, 11);
        assert_eq!(state.sessions.len(), 1);
    }

    #[tokio::test]
    async fn delete_existing_session_removes_it() {
        let (state, _index_dir) = test_state(1800, 2).await;
        assert!(matches!(
            session_server(&state, "session-1", false, Instant::now()),
            SessionLookup::Ready(_)
        ));

        let mut headers = HeaderMap::new();
        headers.insert(MCP_SESSION_ID_HEADER, HeaderValue::from_static("session-1"));

        let response = handle_mcp_delete(State(state.clone()), headers)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(state.sessions.len(), 0);
    }

    #[tokio::test]
    async fn get_with_unknown_session_returns_not_found() {
        let (state, _index_dir) = test_state(1800, 2).await;
        let mut headers = HeaderMap::new();
        headers.insert(MCP_SESSION_ID_HEADER, HeaderValue::from_static("missing"));

        let response = handle_mcp_get(State(state), headers).await.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response
                .headers()
                .get(MCP_SESSION_ID_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("missing")
        );
    }

    #[tokio::test]
    async fn delete_unknown_session_returns_not_found() {
        let (state, _index_dir) = test_state(1800, 2).await;
        let mut headers = HeaderMap::new();
        headers.insert(MCP_SESSION_ID_HEADER, HeaderValue::from_static("missing"));

        let response = handle_mcp_delete(State(state), headers)
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_reports_safe_session_diagnostics() {
        let (state, _index_dir) = test_state(1800, 2).await;
        assert!(matches!(
            session_server(&state, "session-1", false, Instant::now()),
            SessionLookup::Ready(_)
        ));

        let response = handle_mcp_get(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("failed to read body");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("failed to parse diagnostics");
        assert_eq!(json["sessions"]["active"], 1);
        assert_eq!(json["sessions"]["max"], 2);
        assert_eq!(json["sessions"]["idle_ttl_seconds"], 1800);
        assert!(json.to_string().contains("session-1") == false);
    }

    #[test]
    fn reads_valid_session_id_header() {
        let mut headers = HeaderMap::new();
        headers.insert(MCP_SESSION_ID_HEADER, HeaderValue::from_static("session-1"));

        assert_eq!(
            session_id_from_headers(&headers).unwrap(),
            Some("session-1".to_string())
        );
    }

    async fn spawn_test_server(state: McpHttpState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test listener");
        let addr = listener.local_addr().expect("failed to read test addr");
        let app = build_router("/mcp", state);

        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test MCP HTTP server failed");
        });

        format!("http://{}/mcp", addr)
    }

    #[tokio::test]
    async fn http_session_lifecycle_is_bounded_and_diagnostic_safe() {
        let (state, _index_dir) = test_state(1800, 1).await;
        let url = spawn_test_server(state).await;
        let client = reqwest::Client::new();

        let first = client
            .post(&url)
            .body(vec![0xff])
            .send()
            .await
            .expect("first request failed");
        assert_eq!(first.status(), reqwest::StatusCode::BAD_REQUEST);
        let session_id = first
            .headers()
            .get(MCP_SESSION_ID_HEADER)
            .expect("missing session header")
            .to_str()
            .expect("invalid session header")
            .to_string();

        let second = client
            .post(&url)
            .body(vec![0xff])
            .send()
            .await
            .expect("second request failed");
        assert_eq!(second.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

        let delete = client
            .delete(&url)
            .header(MCP_SESSION_ID_HEADER, &session_id)
            .send()
            .await
            .expect("delete request failed");
        assert_eq!(delete.status(), reqwest::StatusCode::NO_CONTENT);

        let diagnostics: serde_json::Value = client
            .get(&url)
            .send()
            .await
            .expect("get request failed")
            .json()
            .await
            .expect("invalid diagnostics json");
        assert_eq!(diagnostics["sessions"]["active"], 0);
        assert_eq!(diagnostics["sessions"]["max"], 1);
        assert_eq!(diagnostics["sessions"]["idle_ttl_seconds"], 1800);
        assert!(!diagnostics.to_string().contains(&session_id));

        let stale = client
            .get(&url)
            .header(MCP_SESSION_ID_HEADER, &session_id)
            .send()
            .await
            .expect("stale get failed");
        assert_eq!(stale.status(), reqwest::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn http_get_prunes_idle_sessions() {
        let (state, _index_dir) = test_state(0, 2).await;
        let url = spawn_test_server(state).await;
        let client = reqwest::Client::new();

        let first = client
            .post(&url)
            .body(vec![0xff])
            .send()
            .await
            .expect("first request failed");
        assert_eq!(first.status(), reqwest::StatusCode::BAD_REQUEST);

        let diagnostics: serde_json::Value = client
            .get(&url)
            .send()
            .await
            .expect("get request failed")
            .json()
            .await
            .expect("invalid diagnostics json");
        assert_eq!(diagnostics["sessions"]["active"], 0);
        assert_eq!(diagnostics["sessions"]["pruned"], 1);
    }
}
