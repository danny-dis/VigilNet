//! VigilNet Metrics and Observability
//!
//! Provides comprehensive metrics collection and monitoring capabilities.
//! Supports Prometheus-compatible metrics exposition via HTTP endpoint.
//!
//! # Example
//!
//! ```ignore
//! use vigilnet_core::metrics::Metrics;
//!
//! let metrics = Metrics::new();
//! metrics.record_connection_established();
//! metrics.increment_bytes_transferred(1024);
//! ```

use metrics::{counter, gauge, histogram, Counter, Gauge, Histogram, Key, Label, Unit};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use prometheus::Registry;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Central metrics collection system for VigilNet
///
/// Provides counters, gauges, and histograms for monitoring
/// all aspects of the VigilNet privacy network.
#[derive(Clone)]
pub struct Metrics {
    /// Inner state protected by lock
    inner: Arc<RwLock<MetricsInner>>,
    /// Prometheus handle for metric exposition
    prometheus_handle: Option<PrometheusHandle>,
    /// Start time for uptime calculation
    started_at: Instant,
}

/// Internal metrics state
struct MetricsInner {
    /// Prometheus registry
    registry: Registry,
    /// Connection metrics
    connection_metrics: ConnectionMetrics,
    /// Crypto metrics
    crypto_metrics: CryptoMetrics,
    /// Agent metrics
    agent_metrics: AgentMetrics,
    /// Error counters by type
    error_counters: ErrorCounters,
    /// Latency histograms
    latency_histograms: LatencyHistograms,
    /// Network metrics
    network_metrics: NetworkMetrics,
    /// System metrics
    system_metrics: SystemMetrics,
}

/// Connection-related metrics
#[derive(Clone, Debug, Default)]
pub struct ConnectionMetrics {
    /// Total connections ever established
    pub total_connections: AtomicU64,
    /// Currently active connections
    pub active_connections: AtomicU64,
    /// Total connection duration in milliseconds
    pub total_connection_duration_ms: AtomicU64,
    /// Failed connection attempts
    pub failed_connections: AtomicU64,
    /// Connection timeouts
    pub connection_timeouts: AtomicU64,
    /// Connection retries
    pub connection_retries: AtomicU64,
}

/// Cryptographic operation metrics
#[derive(Clone, Debug, Default)]
pub struct CryptoMetrics {
    /// Total bytes encrypted
    pub bytes_encrypted: AtomicU64,
    /// Total bytes decrypted
    pub bytes_decrypted: AtomicU64,
    /// Total encryption time in microseconds
    pub encryption_time_us: AtomicU64,
    /// Total decryption time in microseconds
    pub decryption_time_us: AtomicU64,
    /// Number of encryption operations
    pub encryption_ops: AtomicU64,
    /// Number of decryption operations
    pub decryption_ops: AtomicU64,
    /// Key exchange operations
    pub key_exchanges: AtomicU64,
    /// Key exchange duration in microseconds
    pub key_exchange_time_us: AtomicU64,
}

/// Agent network metrics
#[derive(Clone, Debug, Default)]
pub struct AgentMetrics {
    /// Number of active agents
    pub active_agents: AtomicU64,
    /// Total messages sent
    pub messages_sent: AtomicU64,
    /// Total messages received
    pub messages_received: AtomicU64,
    /// Total bytes sent via agents
    pub bytes_sent: AtomicU64,
    /// Total bytes received via agents
    pub bytes_received: AtomicU64,
    /// Active sessions
    pub active_sessions: AtomicU64,
    /// Session establishment count
    pub sessions_established: AtomicU64,
    /// Session failures
    pub session_failures: AtomicU64,
}

/// Error counters organized by type
#[derive(Clone, Debug, Default)]
pub struct ErrorCounters {
    /// Network errors
    pub network_errors: AtomicU64,
    /// Crypto errors
    pub crypto_errors: AtomicU64,
    /// Routing errors
    pub routing_errors: AtomicU64,
    /// Protocol errors
    pub protocol_errors: AtomicU64,
    /// Timeout errors
    pub timeout_errors: AtomicU64,
    /// Authentication errors
    pub auth_errors: AtomicU64,
    /// IO errors
    pub io_errors: AtomicU64,
    /// Internal errors
    pub internal_errors: AtomicU64,
}

/// Latency histogram buckets
#[derive(Clone, Debug)]
pub struct LatencyHistograms {
    /// Connection establishment latency
    pub connection_latency: Histogram,
    /// Encryption/decryption latency
    pub crypto_latency: Histogram,
    /// Message routing latency
    pub routing_latency: Histogram,
    /// Key exchange latency
    pub key_exchange_latency: Histogram,
    /// Database operation latency
    pub db_latency: Histogram,
    /// Overall request latency
    pub request_latency: Histogram,
}

/// Network-level metrics
#[derive(Clone, Debug, Default)]
pub struct NetworkMetrics {
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// Total bytes received
    pub bytes_received: AtomicU64,
    /// Total packets sent
    pub packets_sent: AtomicU64,
    /// Total packets received
    pub packets_received: AtomicU64,
    /// Packets dropped
    pub packets_dropped: AtomicU64,
    /// Retransmissions
    pub retransmissions: AtomicU64,
    /// Circuit builds initiated
    pub circuit_builds: AtomicU64,
    /// Successful circuit builds
    pub circuit_builds_success: AtomicU64,
    /// Failed circuit builds
    pub circuit_builds_failed: AtomicU64,
}

/// System-level metrics
#[derive(Clone, Debug, Default)]
pub struct SystemMetrics {
    /// Memory usage in bytes
    pub memory_usage_bytes: AtomicU64,
    /// Number of active tasks
    pub active_tasks: AtomicU64,
    /// Number of active threads
    pub active_threads: AtomicU64,
    /// File descriptors open
    pub open_fds: AtomicU64,
    /// CPU usage percentage (0-10000, divide by 100 for actual %)
    pub cpu_usage_percent: AtomicU64,
}

/// Metric labels for categorization
#[derive(Clone, Debug)]
pub struct MetricLabels {
    /// Component name
    pub component: String,
    /// Operation type
    pub operation: String,
    /// Status (success/error)
    pub status: String,
}

impl MetricLabels {
    /// Create new metric labels
    pub fn new(component: &str, operation: &str, status: &str) -> Self {
        Self {
            component: component.to_string(),
            operation: operation.to_string(),
            status: status.to_string(),
        }
    }

    /// Convert to metrics labels
    pub fn to_labels(&self) -> Vec<Label> {
        vec![
            Label::new("component", self.component.clone()),
            Label::new("operation", self.operation.clone()),
            Label::new("status", self.status.clone()),
        ]
    }
}

impl Metrics {
    /// Create a new metrics system
    ///
    /// Initializes all metrics collectors and registers them with
    /// the Prometheus registry.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vigilnet_core::metrics::Metrics;
    ///
    /// let metrics = Metrics::new();
    /// ```
    pub fn new() -> Self {
        let registry = Registry::new();
        
        let inner = Arc::new(RwLock::new(MetricsInner {
            registry,
            connection_metrics: ConnectionMetrics::default(),
            crypto_metrics: CryptoMetrics::default(),
            agent_metrics: AgentMetrics::default(),
            error_counters: ErrorCounters::default(),
            latency_histograms: Self::create_latency_histograms(),
            network_metrics: NetworkMetrics::default(),
            system_metrics: SystemMetrics::default(),
        }));

        // Install metrics recorder
        let recorder = PrometheusBuilder::new().build_recorder();
        let prometheus_handle = recorder.handle();
        
        // Set as global recorder
        if let Err(e) = metrics::set_global_recorder(recorder) {
            warn!("Failed to set global metrics recorder: {}", e);
        }

        Self {
            inner,
            prometheus_handle: Some(prometheus_handle),
            started_at: Instant::now(),
        }
    }

    /// Create latency histograms with appropriate buckets
    fn create_latency_histograms() -> LatencyHistograms {
        // Define exponential buckets: 0.1ms, 0.5ms, 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s
        let buckets = vec![
            0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0,
        ];

        LatencyHistograms {
            connection_latency: histogram!("vigilnet_connection_latency_seconds", &buckets),
            crypto_latency: histogram!("vigilnet_crypto_latency_seconds", &buckets),
            routing_latency: histogram!("vigilnet_routing_latency_seconds", &buckets),
            key_exchange_latency: histogram!("vigilnet_key_exchange_latency_seconds", &buckets),
            db_latency: histogram!("vigilnet_db_latency_seconds", &buckets),
            request_latency: histogram!("vigilnet_request_latency_seconds", &buckets),
        }
    }

    /// Start the Prometheus metrics HTTP server
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind the metrics server to
    ///
    /// # Returns
    ///
    /// JoinHandle for the server task
    ///
    /// # Example
    ///
    /// ```ignore
    /// let metrics = Metrics::new();
    /// let handle = metrics.start_server("0.0.0.0:9090".parse().unwrap()).await;
    /// ```
    pub async fn start_server(&self, addr: SocketAddr) -> tokio::task::JoinHandle<()> {
        let inner = Arc::clone(&self.inner);
        
        tokio::spawn(async move {
            use tokio::net::TcpListener;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    error!("Failed to bind metrics server to {}: {}", addr, e);
                    return;
                }
            };
            
            info!("Metrics server listening on http://{}/metrics", addr);
            
            loop {
                match listener.accept().await {
                    Ok((mut stream, peer_addr)) => {
                        debug!("Metrics request from {}", peer_addr);
                        
                        let inner_clone = Arc::clone(&inner);
                        tokio::spawn(async move {
                            let mut buffer = [0u8; 1024];
                            
                            match stream.read(&mut buffer).await {
                                Ok(n) if n > 0 => {
                                    let request = String::from_utf8_lossy(&buffer[..n]);
                                    
                                    let response = if request.starts_with("GET /metrics") {
                                        match inner_clone.read().await.render_prometheus() {
                                            Ok(metrics) => format!(
                                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                                                metrics.len(),
                                                metrics
                                            ),
                                            Err(e) => format!(
                                                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\nFailed to render metrics: {}",
                                                e.len(),
                                                e
                                            ),
                                        }
                                    } else if request.starts_with("GET /health") {
                                        Self::health_response(&inner_clone).await
                                    } else {
                                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()
                                    };
                                    
                                    let _ = stream.write_all(response.as_bytes()).await;
                                }
                                _ => {}
                            }
                        });
                    }
                    Err(e) => {
                        warn!("Failed to accept metrics connection: {}", e);
                    }
                }
            }
        })
    }

    /// Generate health check response
    async fn health_response(inner: &Arc<RwLock<MetricsInner>>) -> String {
        let health = inner.read().await.health_check().await;
        let body = serde_json::to_string(&health).unwrap_or_else(|_| "{\"status\":\"error\"}".to_string());
        
        format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            if health.status == "healthy" { "200 OK" } else { "503 Service Unavailable" },
            body.len(),
            body
        )
    }

    // ========== Connection Metrics ==========

    /// Record a new connection establishment
    pub fn record_connection_established(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.connection_metrics.total_connections.fetch_add(1, Ordering::Relaxed);
            inner.connection_metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_connections_total").increment(1);
        gauge!("vigilnet_connections_active").increment(1.0);
    }

    /// Record a connection close
    pub fn record_connection_closed(&self, duration: Duration) {
        if let Ok(inner) = self.inner.try_read() {
            inner.connection_metrics.active_connections.fetch_sub(1, Ordering::Relaxed);
            inner.connection_metrics.total_connection_duration_ms.fetch_add(
                duration.as_millis() as u64,
                Ordering::Relaxed,
            );
        }
        gauge!("vigilnet_connections_active").decrement(1.0);
        histogram!("vigilnet_connection_duration_seconds").record(duration.as_secs_f64());
    }

    /// Record connection failure
    pub fn record_connection_failed(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.connection_metrics.failed_connections.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_connection_failures_total").increment(1);
    }

    /// Record connection timeout
    pub fn record_connection_timeout(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.connection_metrics.connection_timeouts.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_connection_timeouts_total").increment(1);
    }

    /// Record connection retry
    pub fn record_connection_retry(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.connection_metrics.connection_retries.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_connection_retries_total").increment(1);
    }

    /// Record connection latency
    pub fn record_connection_latency(&self, latency: Duration) {
        if let Ok(inner) = self.inner.try_read() {
            inner.latency_histograms.connection_latency.record(latency.as_secs_f64());
        }
    }

    // ========== Crypto Metrics ==========

    /// Record bytes encrypted
    pub fn record_bytes_encrypted(&self, bytes: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.crypto_metrics.bytes_encrypted.fetch_add(bytes, Ordering::Relaxed);
            inner.crypto_metrics.encryption_ops.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_crypto_bytes_encrypted_total").increment(bytes);
        counter!("vigilnet_crypto_encryption_operations_total").increment(1);
    }

    /// Record bytes decrypted
    pub fn record_bytes_decrypted(&self, bytes: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.crypto_metrics.bytes_decrypted.fetch_add(bytes, Ordering::Relaxed);
            inner.crypto_metrics.decryption_ops.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_crypto_bytes_decrypted_total").increment(bytes);
        counter!("vigilnet_crypto_decryption_operations_total").increment(1);
    }

    /// Record encryption time
    pub fn record_encryption_time(&self, duration: Duration) {
        if let Ok(inner) = self.inner.try_read() {
            inner.crypto_metrics.encryption_time_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
            inner.latency_histograms.crypto_latency.record(duration.as_secs_f64());
        }
        histogram!("vigilnet_crypto_encryption_duration_seconds").record(duration.as_secs_f64());
    }

    /// Record decryption time
    pub fn record_decryption_time(&self, duration: Duration) {
        if let Ok(inner) = self.inner.try_read() {
            inner.crypto_metrics.decryption_time_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        }
        histogram!("vigilnet_crypto_decryption_duration_seconds").record(duration.as_secs_f64());
    }

    /// Record key exchange
    pub fn record_key_exchange(&self, duration: Duration) {
        if let Ok(inner) = self.inner.try_read() {
            inner.crypto_metrics.key_exchanges.fetch_add(1, Ordering::Relaxed);
            inner.crypto_metrics.key_exchange_time_us.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
            inner.latency_histograms.key_exchange_latency.record(duration.as_secs_f64());
        }
        counter!("vigilnet_crypto_key_exchanges_total").increment(1);
        histogram!("vigilnet_crypto_key_exchange_duration_seconds").record(duration.as_secs_f64());
    }

    // ========== Agent Metrics ==========

    /// Record agent connected
    pub fn record_agent_connected(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.agent_metrics.active_agents.fetch_add(1, Ordering::Relaxed);
        }
        gauge!("vigilnet_agents_active").increment(1.0);
    }

    /// Record agent disconnected
    pub fn record_agent_disconnected(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.agent_metrics.active_agents.fetch_sub(1, Ordering::Relaxed);
        }
        gauge!("vigilnet_agents_active").decrement(1.0);
    }

    /// Record message sent via agent
    pub fn record_agent_message_sent(&self, bytes: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.agent_metrics.messages_sent.fetch_add(1, Ordering::Relaxed);
            inner.agent_metrics.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        }
        counter!("vigilnet_agent_messages_sent_total").increment(1);
        counter!("vigilnet_agent_bytes_sent_total").increment(bytes);
    }

    /// Record message received via agent
    pub fn record_agent_message_received(&self, bytes: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.agent_metrics.messages_received.fetch_add(1, Ordering::Relaxed);
            inner.agent_metrics.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        }
        counter!("vigilnet_agent_messages_received_total").increment(1);
        counter!("vigilnet_agent_bytes_received_total").increment(bytes);
    }

    /// Record session established
    pub fn record_session_established(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.agent_metrics.active_sessions.fetch_add(1, Ordering::Relaxed);
            inner.agent_metrics.sessions_established.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_agent_sessions_established_total").increment(1);
        gauge!("vigilnet_agent_sessions_active").increment(1.0);
    }

    /// Record session closed
    pub fn record_session_closed(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.agent_metrics.active_sessions.fetch_sub(1, Ordering::Relaxed);
        }
        gauge!("vigilnet_agent_sessions_active").decrement(1.0);
    }

    /// Record session failure
    pub fn record_session_failed(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.agent_metrics.session_failures.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_agent_session_failures_total").increment(1);
    }

    // ========== Error Metrics ==========

    /// Record a network error
    pub fn record_network_error(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.error_counters.network_errors.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_errors_total", "type" => "network").increment(1);
    }

    /// Record a crypto error
    pub fn record_crypto_error(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.error_counters.crypto_errors.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_errors_total", "type" => "crypto").increment(1);
    }

    /// Record a routing error
    pub fn record_routing_error(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.error_counters.routing_errors.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_errors_total", "type" => "routing").increment(1);
    }

    /// Record a protocol error
    pub fn record_protocol_error(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.error_counters.protocol_errors.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_errors_total", "type" => "protocol").increment(1);
    }

    /// Record a timeout error
    pub fn record_timeout_error(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.error_counters.timeout_errors.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_errors_total", "type" => "timeout").increment(1);
    }

    /// Record an authentication error
    pub fn record_auth_error(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.error_counters.auth_errors.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_errors_total", "type" => "auth").increment(1);
    }

    /// Record an IO error
    pub fn record_io_error(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.error_counters.io_errors.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_errors_total", "type" => "io").increment(1);
    }

    /// Record an internal error
    pub fn record_internal_error(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.error_counters.internal_errors.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_errors_total", "type" => "internal").increment(1);
    }

    // ========== Network Metrics ==========

    /// Record bytes sent
    pub fn record_bytes_sent(&self, bytes: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.network_metrics.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
            inner.network_metrics.packets_sent.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_network_bytes_sent_total").increment(bytes);
        counter!("vigilnet_network_packets_sent_total").increment(1);
    }

    /// Record bytes received
    pub fn record_bytes_received(&self, bytes: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.network_metrics.bytes_received.fetch_add(bytes, Ordering::Relaxed);
            inner.network_metrics.packets_received.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_network_bytes_received_total").increment(bytes);
        counter!("vigilnet_network_packets_received_total").increment(1);
    }

    /// Record packet dropped
    pub fn record_packet_dropped(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.network_metrics.packets_dropped.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_network_packets_dropped_total").increment(1);
    }

    /// Record retransmission
    pub fn record_retransmission(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.network_metrics.retransmissions.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_network_retransmissions_total").increment(1);
    }

    /// Record circuit build attempt
    pub fn record_circuit_build(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.network_metrics.circuit_builds.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_circuit_builds_total").increment(1);
    }

    /// Record successful circuit build
    pub fn record_circuit_build_success(&self, duration: Duration) {
        if let Ok(inner) = self.inner.try_read() {
            inner.network_metrics.circuit_builds_success.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_circuit_builds_success_total").increment(1);
        histogram!("vigilnet_circuit_build_duration_seconds").record(duration.as_secs_f64());
    }

    /// Record failed circuit build
    pub fn record_circuit_build_failed(&self) {
        if let Ok(inner) = self.inner.try_read() {
            inner.network_metrics.circuit_builds_failed.fetch_add(1, Ordering::Relaxed);
        }
        counter!("vigilnet_circuit_builds_failed_total").increment(1);
    }

    // ========== System Metrics ==========

    /// Update memory usage
    pub fn update_memory_usage(&self, bytes: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.system_metrics.memory_usage_bytes.store(bytes, Ordering::Relaxed);
        }
        gauge!("vigilnet_system_memory_bytes").set(bytes as f64);
    }

    /// Update active tasks count
    pub fn update_active_tasks(&self, count: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.system_metrics.active_tasks.store(count, Ordering::Relaxed);
        }
        gauge!("vigilnet_system_active_tasks").set(count as f64);
    }

    /// Update active threads count
    pub fn update_active_threads(&self, count: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.system_metrics.active_threads.store(count, Ordering::Relaxed);
        }
        gauge!("vigilnet_system_active_threads").set(count as f64);
    }

    /// Update open file descriptors
    pub fn update_open_fds(&self, count: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.system_metrics.open_fds.store(count, Ordering::Relaxed);
        }
        gauge!("vigilnet_system_open_fds").set(count as f64);
    }

    /// Update CPU usage (percentage * 100)
    pub fn update_cpu_usage(&self, percent_times_100: u64) {
        if let Ok(inner) = self.inner.try_read() {
            inner.system_metrics.cpu_usage_percent.store(percent_times_100, Ordering::Relaxed);
        }
        gauge!("vigilnet_system_cpu_percent").set(percent_times_100 as f64 / 100.0);
    }

    // ========== General Metrics ==========

    /// Get current uptime
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Get Prometheus metrics output
    pub fn prometheus_output(&self) -> Option<String> {
        self.prometheus_handle.as_ref().map(|h| h.render())
    }

    /// Get all metrics snapshot
    pub async fn get_snapshot(&self) -> MetricsSnapshot {
        let inner = self.inner.read().await;
        
        MetricsSnapshot {
            uptime_secs: self.uptime().as_secs(),
            connections: ConnectionSnapshot {
                total: inner.connection_metrics.total_connections.load(Ordering::Relaxed),
                active: inner.connection_metrics.active_connections.load(Ordering::Relaxed),
                failed: inner.connection_metrics.failed_connections.load(Ordering::Relaxed),
            },
            crypto: CryptoSnapshot {
                bytes_encrypted: inner.crypto_metrics.bytes_encrypted.load(Ordering::Relaxed),
                bytes_decrypted: inner.crypto_metrics.bytes_decrypted.load(Ordering::Relaxed),
                encryption_ops: inner.crypto_metrics.encryption_ops.load(Ordering::Relaxed),
                decryption_ops: inner.crypto_metrics.decryption_ops.load(Ordering::Relaxed),
                key_exchanges: inner.crypto_metrics.key_exchanges.load(Ordering::Relaxed),
            },
            agents: AgentSnapshot {
                active: inner.agent_metrics.active_agents.load(Ordering::Relaxed),
                messages_sent: inner.agent_metrics.messages_sent.load(Ordering::Relaxed),
                messages_received: inner.agent_metrics.messages_received.load(Ordering::Relaxed),
                sessions_active: inner.agent_metrics.active_sessions.load(Ordering::Relaxed),
            },
            errors: ErrorSnapshot {
                network: inner.error_counters.network_errors.load(Ordering::Relaxed),
                crypto: inner.error_counters.crypto_errors.load(Ordering::Relaxed),
                routing: inner.error_counters.routing_errors.load(Ordering::Relaxed),
                protocol: inner.error_counters.protocol_errors.load(Ordering::Relaxed),
                timeout: inner.error_counters.timeout_errors.load(Ordering::Relaxed),
                auth: inner.error_counters.auth_errors.load(Ordering::Relaxed),
                io: inner.error_counters.io_errors.load(Ordering::Relaxed),
                internal: inner.error_counters.internal_errors.load(Ordering::Relaxed),
            },
            network: NetworkSnapshot {
                bytes_sent: inner.network_metrics.bytes_sent.load(Ordering::Relaxed),
                bytes_received: inner.network_metrics.bytes_received.load(Ordering::Relaxed),
                packets_sent: inner.network_metrics.packets_sent.load(Ordering::Relaxed),
                packets_received: inner.network_metrics.packets_received.load(Ordering::Relaxed),
                packets_dropped: inner.network_metrics.packets_dropped.load(Ordering::Relaxed),
                circuits_built: inner.network_metrics.circuit_builds_success.load(Ordering::Relaxed),
            },
            system: SystemSnapshot {
                memory_bytes: inner.system_metrics.memory_usage_bytes.load(Ordering::Relaxed),
                active_tasks: inner.system_metrics.active_tasks.load(Ordering::Relaxed),
                active_threads: inner.system_metrics.active_threads.load(Ordering::Relaxed),
                open_fds: inner.system_metrics.open_fds.load(Ordering::Relaxed),
                cpu_percent: inner.system_metrics.cpu_usage_percent.load(Ordering::Relaxed) as f64 / 100.0,
            },
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of all metrics at a point in time
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsSnapshot {
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Connection metrics
    pub connections: ConnectionSnapshot,
    /// Crypto metrics
    pub crypto: CryptoSnapshot,
    /// Agent metrics
    pub agents: AgentSnapshot,
    /// Error counts
    pub errors: ErrorSnapshot,
    /// Network metrics
    pub network: NetworkSnapshot,
    /// System metrics
    pub system: SystemSnapshot,
}

/// Connection metrics snapshot
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionSnapshot {
    pub total: u64,
    pub active: u64,
    pub failed: u64,
}

/// Crypto metrics snapshot
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CryptoSnapshot {
    pub bytes_encrypted: u64,
    pub bytes_decrypted: u64,
    pub encryption_ops: u64,
    pub decryption_ops: u64,
    pub key_exchanges: u64,
}

/// Agent metrics snapshot
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentSnapshot {
    pub active: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub sessions_active: u64,
}

/// Error counts snapshot
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ErrorSnapshot {
    pub network: u64,
    pub crypto: u64,
    pub routing: u64,
    pub protocol: u64,
    pub timeout: u64,
    pub auth: u64,
    pub io: u64,
    pub internal: u64,
}

/// Network metrics snapshot
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub circuits_built: u64,
}

/// System metrics snapshot
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemSnapshot {
    pub memory_bytes: u64,
    pub active_tasks: u64,
    pub active_threads: u64,
    pub open_fds: u64,
    pub cpu_percent: f64,
}

/// Timer for measuring operation duration
pub struct Timer {
    start: Instant,
    metric_name: &'static str,
}

impl Timer {
    /// Create a new timer for the given metric
    pub fn new(metric_name: &'static str) -> Self {
        Self {
            start: Instant::now(),
            metric_name,
        }
    }

    /// Record the elapsed time
    pub fn record(self) -> Duration {
        let duration = self.start.elapsed();
        histogram!(self.metric_name).record(duration.as_secs_f64());
        duration
    }
}

/// Scoped timer that records on drop
pub struct ScopedTimer {
    start: Instant,
    metric_name: &'static str,
}

impl ScopedTimer {
    /// Create a new scoped timer
    pub fn new(metric_name: &'static str) -> Self {
        Self {
            start: Instant::now(),
            metric_name,
        }
    }
}

impl Drop for ScopedTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        histogram!(self.metric_name).record(duration.as_secs_f64());
    }
}

impl MetricsInner {
    /// Render Prometheus-compatible metrics
    async fn render_prometheus(&self) -> Result<String, String> {
        // This would use the prometheus registry to render
        // For now, return a simple formatted output
        let mut output = String::new();
        
        // Add standard Prometheus metrics
        output.push_str("# HELP vigilnet_connections_total Total connections established\n");
        output.push_str("# TYPE vigilnet_connections_total counter\n");
        output.push_str(&format!("vigilnet_connections_total {}\n", 
            self.connection_metrics.total_connections.load(Ordering::Relaxed)));
        
        output.push_str("# HELP vigilnet_connections_active Currently active connections\n");
        output.push_str("# TYPE vigilnet_connections_active gauge\n");
        output.push_str(&format!("vigilnet_connections_active {}\n",
            self.connection_metrics.active_connections.load(Ordering::Relaxed)));
        
        // Add more metrics...
        Ok(output)
    }

    /// Perform health check
    async fn health_check(&self) -> HealthStatus {
        let errors = self.get_total_errors();
        let active_connections = self.connection_metrics.active_connections.load(Ordering::Relaxed);
        
        HealthStatus {
            status: if errors > 100 { "degraded" } else { "healthy" },
            version: crate::VERSION.to_string(),
            uptime_secs: 0, // Will be filled by caller
            components: vec![
                ComponentHealth {
                    name: "network".to_string(),
                    status: if active_connections > 0 { "ok" } else { "warning" }.to_string(),
                    message: format!("{} active connections", active_connections),
                },
                ComponentHealth {
                    name: "crypto".to_string(),
                    status: "ok".to_string(),
                    message: "Cryptographic subsystem operational".to_string(),
                },
            ],
        }
    }

    /// Get total error count
    fn get_total_errors(&self) -> u64 {
        self.error_counters.network_errors.load(Ordering::Relaxed)
            + self.error_counters.crypto_errors.load(Ordering::Relaxed)
            + self.error_counters.routing_errors.load(Ordering::Relaxed)
            + self.error_counters.protocol_errors.load(Ordering::Relaxed)
            + self.error_counters.timeout_errors.load(Ordering::Relaxed)
            + self.error_counters.auth_errors.load(Ordering::Relaxed)
            + self.error_counters.io_errors.load(Ordering::Relaxed)
            + self.error_counters.internal_errors.load(Ordering::Relaxed)
    }
}

/// Health check status
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthStatus {
    /// Overall status: "healthy", "degraded", "unhealthy"
    pub status: String,
    /// Software version
    pub version: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Component health details
    pub components: Vec<ComponentHealth>,
}

/// Individual component health
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Component status: "ok", "warning", "error"
    pub status: String,
    /// Status message
    pub message: String,
}

/// Global metrics instance (optional, for convenience)
static mut GLOBAL_METRICS: Option<Metrics> = None;

/// Initialize global metrics
pub fn init_global_metrics() {
    unsafe {
        GLOBAL_METRICS = Some(Metrics::new());
    }
}

/// Get global metrics instance
pub fn global_metrics() -> Option<&'static Metrics> {
    unsafe { GLOBAL_METRICS.as_ref() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new() {
        let metrics = Metrics::new();
        assert!(metrics.prometheus_output().is_some());
    }

    #[test]
    fn test_connection_metrics() {
        let metrics = Metrics::new();
        
        metrics.record_connection_established();
        metrics.record_connection_closed(Duration::from_secs(5));
        metrics.record_connection_failed();
        
        // Metrics should be recorded
    }

    #[test]
    fn test_crypto_metrics() {
        let metrics = Metrics::new();
        
        metrics.record_bytes_encrypted(1024);
        metrics.record_bytes_decrypted(512);
        metrics.record_encryption_time(Duration::from_micros(100));
        metrics.record_key_exchange(Duration::from_millis(10));
        
        // Metrics should be recorded
    }

    #[test]
    fn test_timer() {
        let timer = Timer::new("test_latency");
        std::thread::sleep(Duration::from_millis(10));
        let duration = timer.record();
        assert!(duration >= Duration::from_millis(10));
    }
}
