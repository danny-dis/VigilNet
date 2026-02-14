use std::time::{Duration, Instant};
use std::collections::VecDeque;

/// Adaptive Padding Manager (CS-BuFLO)
/// 
/// Implements Constant-Rate Traffic to mask true traffic patterns.
/// - If real traffic present: Send it
/// - If no traffic: Send padding (Drop cells)
/// - If traffic > rate: Queue it
pub struct AdaptivePadding {
    /// Target interval between cells
    interval: Duration,
    /// Last time a cell was sent
    last_sent: Instant,
    /// Queue of pending payloads (if rate limited)
    queue: VecDeque<Vec<u8>>,
    /// Enabled state
    enabled: bool,
}

impl AdaptivePadding {
    pub fn new(rate_per_second: u32) -> Self {
        let interval = Duration::from_micros(1_000_000 / rate_per_second as u64);
        Self {
            interval,
            last_sent: Instant::now(),
            queue: VecDeque::new(),
            enabled: true,
        }
    }

    /// Update the padding state and determine next action
    /// Returns:
    /// - Some(payload): Data to send (Real or Padding)
    /// - None: Wait (rate limit enforced)
    pub fn poll(&mut self, real_traffic: Option<Vec<u8>>) -> Option<Vec<u8>> {
        if !self.enabled {
            return real_traffic;
        }

        // Add real traffic to queue if present
        if let Some(data) = real_traffic {
            self.queue.push_back(data);
        }

        let now = Instant::now();
        if now.duration_since(self.last_sent) >= self.interval {
            self.last_sent = now;

            if let Some(data) = self.queue.pop_front() {
                // Send real data
                Some(data)
            } else {
                // Send padding (Empty payload, caller should wrap in Drop cell)
                Some(vec![0u8; 512]) // Standard fixed cell size padding
            }
        } else {
            // Wait for next tick
            None
        }
    }
}
