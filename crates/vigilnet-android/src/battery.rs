//! Battery-Aware Scheduling
//!
//! Monitors Android battery state and adjusts network behavior
//! to minimize power consumption on mobile devices.

use serde::{Deserialize, Serialize};
use tracing::{info, debug};

/// Battery state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatteryState {
    /// Charging (AC/USB/Wireless)
    Charging,
    /// On battery power
    Discharging,
    /// Fully charged
    Full,
    /// Unknown state
    Unknown,
}

/// Power profile for network behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerProfile {
    /// Maximum performance (all features enabled)
    Performance,
    /// Balanced (normal operation)
    Balanced,
    /// Power saver (reduce background activity)
    PowerSaver,
    /// Ultra-low power (minimal networking)
    UltraLow,
}

/// Battery-aware scheduler
pub struct BatteryScheduler {
    /// Current battery level (0-100)
    battery_level: u8,
    /// Current battery state
    battery_state: BatteryState,
    /// Active power profile
    profile: PowerProfile,
    /// Whether relay mode should be active
    relay_enabled: bool,
    /// Background refresh interval (seconds)
    refresh_interval_secs: u64,
}

impl BatteryScheduler {
    /// Create a new scheduler
    pub fn new() -> Self {
        Self {
            battery_level: 100,
            battery_state: BatteryState::Unknown,
            profile: PowerProfile::Balanced,
            relay_enabled: true,
            refresh_interval_secs: 30,
        }
    }

    /// Update battery status (called from Android BatteryManager via JNI)
    pub fn update_battery(&mut self, level: u8, charging: bool) {
        self.battery_level = level;
        self.battery_state = if charging {
            if level >= 100 { BatteryState::Full } else { BatteryState::Charging }
        } else {
            BatteryState::Discharging
        };

        // Auto-adjust profile
        self.profile = self.compute_profile();
        self.apply_profile();

        debug!(
            "Battery: {}% ({:?}), Profile: {:?}",
            level, self.battery_state, self.profile
        );
    }

    /// Get current power profile
    pub fn profile(&self) -> PowerProfile {
        self.profile
    }

    /// Whether relay mode should be active
    pub fn should_relay(&self) -> bool {
        self.relay_enabled && matches!(self.profile, PowerProfile::Performance | PowerProfile::Balanced)
    }

    /// Get the recommended refresh interval
    pub fn refresh_interval(&self) -> u64 {
        self.refresh_interval_secs
    }

    /// Whether background circuit building should be active
    pub fn should_preemptive_circuit_build(&self) -> bool {
        !matches!(self.profile, PowerProfile::UltraLow)
    }

    /// Maximum number of concurrent circuits
    pub fn max_circuits(&self) -> usize {
        match self.profile {
            PowerProfile::Performance => 10,
            PowerProfile::Balanced => 5,
            PowerProfile::PowerSaver => 2,
            PowerProfile::UltraLow => 1,
        }
    }

    fn compute_profile(&self) -> PowerProfile {
        match (self.battery_state, self.battery_level) {
            (BatteryState::Charging | BatteryState::Full, _) => PowerProfile::Performance,
            (_, level) if level > 50 => PowerProfile::Balanced,
            (_, level) if level > 20 => PowerProfile::PowerSaver,
            _ => PowerProfile::UltraLow,
        }
    }

    fn apply_profile(&mut self) {
        match self.profile {
            PowerProfile::Performance => {
                self.relay_enabled = true;
                self.refresh_interval_secs = 15;
            }
            PowerProfile::Balanced => {
                self.relay_enabled = true;
                self.refresh_interval_secs = 30;
            }
            PowerProfile::PowerSaver => {
                self.relay_enabled = false;
                self.refresh_interval_secs = 60;
            }
            PowerProfile::UltraLow => {
                self.relay_enabled = false;
                self.refresh_interval_secs = 120;
            }
        }

        info!(
            "Power profile: {:?} (relay={}, refresh={}s)",
            self.profile, self.relay_enabled, self.refresh_interval_secs
        );
    }
}

impl Default for BatteryScheduler {
    fn default() -> Self {
        Self::new()
    }
}
