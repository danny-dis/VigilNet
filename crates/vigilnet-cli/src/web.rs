use axum::{
    extract::State,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use vigilnet_core::Node;

/// Shared state for the web server
struct AppState {
    node: Arc<Node>,
}

/// Run the web server
pub async fn run_server(node: Arc<Node>, port: u16) -> anyhow::Result<()> {
    let state = Arc::new(AppState { node });

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/status", get(status_handler))
        //.route("/api/config", post(config_handler))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    tracing::info!("Web UI listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Serve the main dashboard HTML
async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

/// API Response for Status
#[derive(Serialize)]
struct StatusResponse {
    peer_id: String,
    peers_count: usize,
    uptime_seconds: u64,
    relay_active: bool,
    version: String,
}

/// Handle status requests
async fn status_handler(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let peers = state.node.peers().await;
    let stats = state.node.stats().await;
    let peer_id = state.node.local_peer_id().await.map(|p| p.to_string()).unwrap_or_else(|| "Unknown".to_string());

    Json(StatusResponse {
        peer_id,
        peers_count: peers.len(),
        uptime_seconds: stats.uptime_secs,
        relay_active: stats.relay_active,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
