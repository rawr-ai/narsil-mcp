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
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::index::CodeIntelEngine;
use crate::mcp::McpServer;

const MCP_SESSION_ID_HEADER: &str = "mcp-session-id";

#[derive(Clone)]
struct McpHttpState {
    engine: Arc<CodeIntelEngine>,
    sessions: Arc<DashMap<String, Arc<McpServer>>>,
}

pub struct McpHttpServer {
    engine: Arc<CodeIntelEngine>,
    host: String,
    port: u16,
    path: String,
}

impl McpHttpServer {
    pub fn new(engine: Arc<CodeIntelEngine>, host: String, port: u16, path: String) -> Self {
        Self {
            engine,
            host,
            port,
            path,
        }
    }

    pub async fn run(self) -> Result<()> {
        let normalized_path = normalize_path(&self.path);
        let state = McpHttpState {
            engine: Arc::clone(&self.engine),
            sessions: Arc::new(DashMap::new()),
        };

        let app = Router::new()
            .route(
                &normalized_path,
                post(handle_mcp_post)
                    .get(handle_mcp_get)
                    .delete(handle_mcp_delete),
            )
            .with_state(state);

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

fn normalize_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

fn get_or_create_session_id(headers: &HeaderMap) -> String {
    headers
        .get(MCP_SESSION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
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

fn session_server(state: &McpHttpState, session_id: &str) -> Arc<McpServer> {
    state
        .sessions
        .entry(session_id.to_string())
        .or_insert_with(|| Arc::new(McpServer::from_arc(Arc::clone(&state.engine))))
        .clone()
}

async fn handle_mcp_post(
    State(state): State<McpHttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let session_id = get_or_create_session_id(&headers);
    let server = session_server(&state, &session_id);

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

async fn handle_mcp_get(headers: HeaderMap) -> impl IntoResponse {
    let session_id = get_or_create_session_id(&headers);
    let response = Json(json!({
        "name": "narsil-mcp",
        "status": "ok",
        "transport": "http",
        "message": "POST JSON-RPC requests to this endpoint"
    }))
    .into_response();
    attach_session_header(response, &session_id)
}

async fn handle_mcp_delete(
    State(state): State<McpHttpState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let session_id = headers
        .get(MCP_SESSION_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    match session_id {
        Some(id) => {
            state.sessions.remove(&id);
            let response = StatusCode::NO_CONTENT.into_response();
            attach_session_header(response, &id)
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
