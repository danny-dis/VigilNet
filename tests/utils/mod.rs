//! Integration Test Utilities for VigilNet
//!
//! This module provides common utilities for integration and E2E tests.

use std::time::Duration;
use tokio::time::timeout;

/// Default timeout for test operations
pub const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Extended timeout for network operations
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);

/// Short timeout for local operations
pub const SHORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Wait for a condition to become true with timeout
pub async fn wait_for<F, Fut>(condition: F, timeout_duration: Duration) -> Result<(), String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if condition().await {
            return Ok(());
        }
        if start.elapsed() > timeout_duration {
            return Err(format!("Timeout after {:?}", timeout_duration));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Retry an async operation with exponential backoff
pub async fn retry_with_backoff<F, Fut, T, E>(
    operation: F,
    max_retries: u32,
    base_delay: Duration,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut delay = base_delay;
    
    for attempt in 0..max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) if attempt == max_retries - 1 => return Err(e),
            Err(_) => {
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
        }
    }
    
    unreachable!()
}

/// Test environment configuration
#[derive(Debug, Clone)]
pub struct TestEnvironment {
    pub bootstrap_nodes: Vec<String>,
    pub tor_proxy: Option<String>,
    pub i2p_sam: Option<String>,
    pub network_latency_ms: u64,
    pub packet_loss_percent: f64,
}

impl Default for TestEnvironment {
    fn default() -> Self {
        Self {
            bootstrap_nodes: vec![
                "/dns4/localhost/tcp/10001".to_string(),
                "/dns4/localhost/tcp/10003".to_string(),
                "/dns4/localhost/tcp/10005".to_string(),
            ],
            tor_proxy: std::env::var("TOR_SOCKS_PROXY").ok(),
            i2p_sam: std::env::var("I2P_SAM_BRIDGE").ok(),
            network_latency_ms: 10,
            packet_loss_percent: 0.0,
        }
    }
}

impl TestEnvironment {
    /// Load from environment variables
    pub fn from_env() -> Self {
        Self::default()
    }
    
    /// Check if test environment is properly configured
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        
        if self.bootstrap_nodes.is_empty() {
            errors.push("No bootstrap nodes configured".to_string());
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Generate test data of specified size
pub fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Generate cryptographically random test data
pub fn generate_random_data(size: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

/// Measure execution time of a block
#[macro_export]
macro_rules! measure_time {
    ($name:expr, $block:expr) => {{
        let start = std::time::Instant::now();
        let result = $block;
        let elapsed = start.elapsed();
        println!("{} took {:?}", $name, elapsed);
        result
    }};
}

/// Assert that a future completes within timeout
#[macro_export]
macro_rules! assert_timeout {
    ($future:expr, $timeout:expr) => {
        match timeout($timeout, $future).await {
            Ok(result) => result,
            Err(_) => panic!("Operation timed out after {:?}", $timeout),
        }
    };
}

/// Test assertion with custom message
#[macro_export]
macro_rules! assert_test {
    ($condition:expr, $msg:expr) => {
        if !$condition {
            panic!("Test assertion failed: {}", $msg);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_wait_for_success() {
        let mut counter = 0;
        let result = wait_for(|| async {
            counter += 1;
            counter >= 3
        }, Duration::from_secs(1)).await;
        
        assert!(result.is_ok());
        assert_eq!(counter, 3);
    }
    
    #[tokio::test]
    async fn test_wait_for_timeout() {
        let result = wait_for(|| async { false }, Duration::from_millis(100)).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_retry_with_backoff() {
        let mut attempts = 0;
        let result: Result<i32, ()> = retry_with_backoff(
            || async {
                attempts += 1;
                if attempts < 3 {
                    Err(())
                } else {
                    Ok(42)
                }
            },
            5,
            Duration::from_millis(10),
        ).await;
        
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 3);
    }
    
    #[test]
    fn test_generate_test_data() {
        let data = generate_test_data(100);
        assert_eq!(data.len(), 100);
        assert_eq!(data[0], 0);
        assert_eq!(data[255], 255);
        assert_eq!(data[256], 0);
    }
    
    #[test]
    fn test_environment_from_env() {
        let env = TestEnvironment::from_env();
        assert!(!env.bootstrap_nodes.is_empty());
    }
}
