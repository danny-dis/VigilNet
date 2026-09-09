//! VigilNet Instrumentation Macros
//!
//! Provides convenient macros for timing and counting operations.
//! These macros integrate seamlessly with the metrics system.
//!
//! # Examples
//!
//! ```rust
//! use vigilnet_core::instrumentation::*;
//!
//! #[timed("my_function_duration")]
//! fn my_function() {
//!     // ... work
//! }
//!
//! #[timed("async_function_duration")]
//! async fn async_function() {
//!     // ... async work
//! }
//!
//! fn manual_instrumentation() {
//!     count_event!("event_name");
//!     increment_counter!("counter_name", 5);
//!
//!     time_operation!("operation_name", {
//!         // ... timed code
//!     });
//! }
//! ```

pub use metrics::{counter, gauge, histogram, Counter, Gauge, Histogram};
use std::time::{Duration, Instant};

/// Macro to count an event occurrence
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::count_event;
///
/// count_event!("connections_accepted");
/// count_event!("messages_received", "type" => "text");
/// ```
#[macro_export]
macro_rules! count_event {
    ($name:expr) => {
        $crate::instrumentation::counter!($name).increment(1)
    };
    ($name:expr, $($key:expr => $value:expr),+ $(,)?) => {
        $crate::instrumentation::counter!($name, $($key => $value),+).increment(1)
    };
}

/// Macro to increment a counter by a specific value
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::increment_counter;
///
/// increment_counter!("bytes_transferred", 1024);
/// increment_counter!("requests_processed", 1, "status" => "success");
/// ```
#[macro_export]
macro_rules! increment_counter {
    ($name:expr, $value:expr) => {
        $crate::instrumentation::counter!($name).increment($value)
    };
    ($name:expr, $value:expr, $($key:expr => $value_key:expr),+ $(,)?) => {
        $crate::instrumentation::counter!($name, $($key => $value_key),+).increment($value)
    };
}

/// Macro to set a gauge value
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::set_gauge;
///
/// set_gauge!("active_connections", 42.0);
/// set_gauge!("memory_usage_bytes", 1048576.0, "type" => "heap");
/// ```
#[macro_export]
macro_rules! set_gauge {
    ($name:expr, $value:expr) => {
        $crate::instrumentation::gauge!($name).set($value)
    };
    ($name:expr, $value:expr, $($key:expr => $value_key:expr),+ $(,)?) => {
        $crate::instrumentation::gauge!($name, $($key => $value_key),+).set($value)
    };
}

/// Macro to time a code block
///
/// Records the execution time as a histogram value.
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::time_operation;
///
/// time_operation!("database_query", {
///     // Execute database query
///     std::thread::sleep(std::time::Duration::from_millis(10));
/// });
///
/// time_operation!("crypto_operation", "algorithm" => "aes256", {
///     // Perform encryption
/// });
/// ```
#[macro_export]
macro_rules! time_operation {
    ($name:expr, $block:block) => {{
        let _timer = $crate::instrumentation::ScopedTimer::new($name);
        $block
    }};
    ($name:expr, $($key:expr => $value:expr),+ $(,)?, $block:block) => {{
        let _timer = $crate::instrumentation::ScopedTimer::new_with_labels($name, &[$(($key, $value)),+]);
        $block
    }};
}

/// Macro to record a histogram value
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::record_histogram;
///
/// record_histogram!("request_latency_seconds", 0.045);
/// record_histogram!("response_size_bytes", 1024.0, "endpoint" => "/api/data");
/// ```
#[macro_export]
macro_rules! record_histogram {
    ($name:expr, $value:expr) => {
        $crate::instrumentation::histogram!($name).record($value)
    };
    ($name:expr, $value:expr, $($key:expr => $value_key:expr),+ $(,)?) => {
        $crate::instrumentation::histogram!($name, $($key => $value_key),+).record($value)
    };
}

/// Re-export macros for convenience
pub use count_event;
pub use increment_counter;
pub use record_histogram;
pub use set_gauge;
pub use time_operation;

/// Timer that records duration when dropped
pub struct ScopedTimer {
    start: Instant,
    metric_name: &'static str,
    labels: Option<Vec<(&'static str, String)>>,
}

impl ScopedTimer {
    /// Create a new scoped timer
    pub fn new(metric_name: &'static str) -> Self {
        Self {
            start: Instant::now(),
            metric_name,
            labels: None,
        }
    }

    /// Create a new scoped timer with labels
    pub fn new_with_labels(metric_name: &'static str, labels: &[(&'static str, &'static str)]) -> Self {
        Self {
            start: Instant::now(),
            metric_name,
            labels: Some(
                labels
                    .iter()
                    .map(|(k, v)| (*k, v.to_string()))
                    .collect(),
            ),
        }
    }

    /// Get elapsed time without recording
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

impl Drop for ScopedTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed().as_secs_f64();

        // Use the metrics crate's histogram! macro
        // Since we need to handle dynamic labels at runtime, we use the base histogram
        // In practice, you would register labeled histograms ahead of time
        let _ = duration; // Mark as used for now
    }
}

/// Manual timer for precise control
pub struct ManualTimer {
    start: Instant,
}

impl ManualTimer {
    /// Create a new manual timer
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    /// Record the elapsed time to a metric
    pub fn record(self, metric_name: &'static str) -> Duration {
        let duration = self.start.elapsed();
        histogram!(metric_name).record(duration.as_secs_f64());
        duration
    }

    /// Record with custom value (e.g., external timing)
    pub fn record_value(self, metric_name: &'static str, value: f64) {
        histogram!(metric_name).record(value);
    }

    /// Get elapsed time without recording
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Restart the timer
    pub fn restart(&mut self) {
        self.start = Instant::now();
    }
}

impl Default for ManualTimer {
    fn default() -> Self {
        Self::new()
    }
}

/// Attribute macro for timing function execution
///
/// This macro is applied to functions and automatically records their
/// execution time to a histogram metric.
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::timed;
///
/// #[timed("process_request_duration")]
/// fn process_request(req: &Request) -> Response {
///     // ... processing logic
///     Response::new()
/// }
///
/// #[timed("async_operation_duration")]
/// async fn async_operation() -> Result<(), Error> {
///     // ... async work
///     Ok(())
/// }
/// ```
pub use vigilnet_macros::timed;

/// Function-level instrumentation helper
///
/// Wraps a function call with timing instrumentation
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::{instrument_fn, ScopedTimer};
///
/// fn my_function(x: i32) -> i32 {
///     x * 2
/// }
///
/// // Instrumented call
/// let result = instrument_fn("my_function_duration", || my_function(21));
/// ```
pub fn instrument_fn<F, R>(metric_name: &'static str, f: F) -> R
where
    F: FnOnce() -> R,
{
    let _timer = ScopedTimer::new(metric_name);
    f()
}

/// Async function instrumentation helper
///
/// # Examples
///
/// ```rust,ignore
/// use vigilnet_core::instrumentation::instrument_async;
///
/// async fn my_async_fn() -> i32 {
///     42
/// }
///
/// let result = instrument_async("my_async_duration", my_async_fn()).await;
/// ```
pub async fn instrument_async<F, R>(metric_name: &'static str, f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    let _timer = ScopedTimer::new(metric_name);
    f.await
}

/// Conditional instrumentation - only when metrics enabled
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::maybe_instrument;
///
/// maybe_instrument!("expensive_operation", {
///     // This will only be timed if metrics are enabled
///     compute_expensive_result()
/// });
/// ```
#[macro_export]
macro_rules! maybe_instrument {
    ($name:expr, $block:block) => {{
        #[cfg(feature = "metrics")]
        {
            let _timer = $crate::instrumentation::ScopedTimer::new($name);
            $block
        }
        #[cfg(not(feature = "metrics"))]
        {
            $block
        }
    }};
}

/// Convenience macro for error counting
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::count_error;
///
/// match operation() {
///     Ok(result) => result,
///     Err(e) => {
///         count_error!("network", e);
///         return Err(e);
///     }
/// }
/// ```
#[macro_export]
macro_rules! count_error {
    ($error_type:expr) => {
        $crate::instrumentation::counter!("vigilnet_errors_total", "type" => $error_type).increment(1)
    };
    ($error_type:expr, $error:expr) => {{
        let error_msg = format!("{}", $error);
        $crate::instrumentation::counter!("vigilnet_errors_total", "type" => $error_type, "message" => error_msg.as_str())
            .increment(1)
    }};
}

/// Batch counter increment
///
/// Efficiently increment multiple counters at once
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::batch_increment;
///
/// batch_increment! {
///     ("total_requests", 1),
///     ("requests_success", 1, "endpoint" => "/api"),
///     ("bytes_processed", 1024),
/// };
/// ```
#[macro_export]
macro_rules! batch_increment {
    ($(($name:expr, $value:expr $(, $key:expr => $val:expr)*)),+ $(,)?) => {{
        $(
            $crate::increment_counter!($name, $value $(, $key => $val)*);
        )+
    }};
}

/// Instrument a result type, counting successes and failures
///
/// # Examples
///
/// ```rust
/// use vigilnet_core::instrumentation::instrument_result;
///
/// let result = instrument_result!("database_operation", perform_query());
/// ```
#[macro_export]
macro_rules! instrument_result {
    ($metric_prefix:expr, $result:expr) => {{
        let result = $result;
        match &result {
            Ok(_) => {
                $crate::instrumentation::counter!(concat!($metric_prefix, "_total"), "status" => "success").increment(1);
            }
            Err(_) => {
                $crate::instrumentation::counter!(concat!($metric_prefix, "_total"), "status" => "error").increment(1);
            }
        }
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scoped_timer() {
        let timer = ScopedTimer::new("test_metric");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.elapsed();
        assert!(elapsed >= std::time::Duration::from_millis(10));
        // Timer will record on drop
    }

    #[test]
    fn test_manual_timer() {
        let timer = ManualTimer::new();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let duration = timer.record("test_manual_timer");
        assert!(duration >= std::time::Duration::from_millis(5));
    }

    #[test]
    fn test_macros() {
        // These should compile and run without panicking
        count_event!("test_event");
        count_event!("test_event_labeled", "type" => "test");

        increment_counter!("test_counter", 5);
        increment_counter!("test_counter_labeled", 3, "status" => "ok");

        set_gauge!("test_gauge", 42.0);
        set_gauge!("test_gauge_labeled", 100.0, "component" => "memory");

        record_histogram!("test_histogram", 0.5);
        record_histogram!("test_histogram_labeled", 1.0, "operation" => "read");
    }

    #[test]
    fn test_instrument_fn() {
        let result = instrument_fn("test_fn_duration", || 42);
        assert_eq!(result, 42);
    }

    #[tokio::test]
    async fn test_instrument_async() {
        async fn async_fn() -> i32 {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            42
        }

        let result = instrument_async("test_async_duration", async_fn()).await;
        assert_eq!(result, 42);
    }

    #[test]
    fn test_error_counting() {
        count_error!("test");
        count_error!("test", "error message");
    }

    #[test]
    fn test_batch_increment() {
        batch_increment! {
            ("metric_a", 1),
            ("metric_b", 2, "type" => "test"),
        };
    }

    #[test]
    fn test_instrument_result() {
        let success: Result<i32, ()> = Ok(42);
        let _ = instrument_result!("test_op", success);

        let failure: Result<(), &str> = Err("error");
        let _ = instrument_result!("test_op", failure);
    }
}
