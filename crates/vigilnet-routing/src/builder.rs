//! Circuit Builder
//!
//! Handles the creation of new circuits with 3-hop path selection and handshake logic.

use crate::{Circuit, CircuitHop, CircuitId, PathSelector, PendingCircuit, Result, RoutingError};
use std::collections::{HashMap, VecDeque};
use tracing::{debug, error, info, instrument, trace, warn};
use vigilnet_crypto::{SessionKey, onion::{CreateCell, CreatedCell, ExtendCell, ExtendedCell}};
use rand::seq::SliceRandom;

/// Configuration for circuit building
#[derive(Clone)]
pub struct BuilderConfig {
    /// Target number of circuits to maintain
    pub target_circuits: usize,
    /// Maximum concurrent building attempts
    pub max_concurrent_builds: usize,
    /// Circuit timeout in seconds
    pub build_timeout_secs: u64,
    /// Whether to prefetch circuits
    pub prefetch_enabled: bool,
}

impl Default for BuilderConfig {
    fn default() -> Self {
        Self {
            target_circuits: 3,
            max_concurrent_builds: 5,
            build_timeout_secs: 30,
            prefetch_enabled: true,
        }
    }
}

/// Builds circuits for the node
pub struct CircuitBuilder {
    /// Path selector for choosing relays
    path_selector: PathSelector,
    /// Circuits currently being built
    pending_circuits: HashMap<CircuitId, PendingCircuit>,
    /// Completed circuits ready for use
    completed_circuits: Vec<Circuit>,
    /// Next circuit ID to assign
    next_circuit_id: u32,
    /// Configuration
    config: BuilderConfig,
    /// Relay info cache for prefetching
    relay_cache: VecDeque<crate::path::RelayInfo>,
}

impl CircuitBuilder {
    /// Create a new circuit builder
    #[instrument(level = "info")]
    pub fn new(path_selector: PathSelector) -> Self {
        info!("Creating new CircuitBuilder with default config");
        Self {
            path_selector,
            pending_circuits: HashMap::new(),
            completed_circuits: Vec::new(),
            next_circuit_id: 1,
            config: BuilderConfig::default(),
            relay_cache: VecDeque::new(),
        }
    }

    /// Create with custom configuration
    #[instrument(skip(path_selector, config), level = "info")]
    pub fn with_config(path_selector: PathSelector, config: BuilderConfig) -> Self {
        info!(
            target_circuits = config.target_circuits,
            max_concurrent_builds = config.max_concurrent_builds,
            "Creating CircuitBuilder with custom config"
        );
        Self {
            path_selector,
            pending_circuits: HashMap::new(),
            completed_circuits: Vec::new(),
            next_circuit_id: 1,
            config,
            relay_cache: VecDeque::new(),
        }
    }

    /// Add a known relay for path selection
    pub fn add_relay(&mut self, info: crate::path::RelayInfo) {
        self.path_selector.add_relay(info.clone());
        if self.relay_cache.len() < 100 {
            self.relay_cache.push_back(info);
        }
    }

    /// Add multiple relays (batch)
    pub fn add_relays(&mut self, infos: Vec<crate::path::RelayInfo>) {
        for info in infos {
            self.add_relay(info);
        }
    }

    /// Get a random relay for prefetch
    fn get_random_relay(&self) -> Option<crate::path::RelayInfo> {
        let mut rng = rand::thread_rng();
        let available: Vec<_> = self.relay_cache.iter().cloned().collect();
        available.choose(&mut rng).cloned()
    }

    /// Prefetch relay info in background
    pub fn prefetch_relay_info(&mut self) {
        if self.relay_cache.len() < 10 {
            debug!("Relay cache low, may need network discovery");
        }
    }

    /// Initialize multiple circuits in parallel (for prefetching)
    pub fn init_multiple_circuits(&mut self, count: usize) -> Vec<Result<(CircuitId, [u8; 32], CreateCell)>> {
        let mut results = Vec::new();
        let max = std::cmp::min(count, self.config.max_concurrent_builds);
        
        for _ in 0..max {
            match self.init_circuit() {
                Ok(result) => results.push(Ok(result)),
                Err(e) => {
                    warn!("Failed to init circuit during prefetch: {}", e);
                    if results.is_empty() {
                        results.push(Err(e));
                    }
                }
            }
        }
        
        results
    }

    /// Get the number of ready circuits
    pub fn ready_count(&self) -> usize {
        self.completed_circuits.len()
    }

    /// Get a ready circuit (oldest first)
    pub fn get_ready_circuit(&mut self) -> Option<Circuit> {
        if self.completed_circuits.is_empty() {
            return None;
        }
        Some(self.completed_circuits.remove(0))
    }

    /// Get all ready circuits
    pub fn get_all_ready_circuits(&self) -> Vec<&Circuit> {
        self.completed_circuits.iter().collect()
    }

    /// Mark a circuit as available again (after use)
    pub fn release_circuit(&mut self, circuit: Circuit) {
        if circuit.is_ready() {
            self.completed_circuits.push(circuit);
        }
    }

    /// Check if we need more circuits
    pub fn needs_more_circuits(&self) -> bool {
        self.completed_circuits.len() < self.config.target_circuits
            && self.pending_circuits.len() < self.config.max_concurrent_builds
    }

    /// Get pending circuit count
    pub fn pending_count(&self) -> usize {
        self.pending_circuits.len()
    }

    /// Initialize a new circuit
    ///
    /// Returns the initial CREATE cell to send to the entry node
    #[instrument(skip(self), level = "info")]
    pub fn init_circuit(&mut self) -> Result<(CircuitId, [u8; 32], CreateCell)> {
        trace!("Selecting 3-hop path for circuit");

        // 1. Select 3 hops
        let hops = self.path_selector.select_path(3).ok_or_else(|| {
            error!("Insufficient relays for 3-hop circuit");
            RoutingError::NoPath("Insufficient relays for 3-hop circuit".into())
        })?;

        let circuit_id = self.next_circuit_id;
        self.next_circuit_id += 1;

        let entry_peer = hops[0].peer_id;
        info!(
            circuit_id,
            entry_peer = ?entry_peer,
            middle_peer = ?hops[1].peer_id,
            exit_peer = ?hops[2].peer_id,
            "Initializing circuit with 3-hop path"
        );

        // 2. Create pending circuit state
        let mut pending = PendingCircuit::new(circuit_id);
        for hop in &hops {
            pending.add_peer(hop.peer_id);
        }

        // 3. Generate first ephemeral key
        trace!("Generating ephemeral key for first hop");
        let (secret, public) = SessionKey::generate_ephemeral();
        pending.add_secret(secret);

        self.pending_circuits.insert(circuit_id, pending);
        debug!(
            circuit_id,
            pending_circuits = self.pending_circuits.len(),
            "Pending circuit created"
        );

        // 4. Create CREATE cell
        trace!("Creating CREATE cell");
        let cell = CreateCell::new(circuit_id, *public.as_bytes());

        info!(circuit_id, "Circuit initialization complete");
        Ok((circuit_id, entry_peer, cell))
    }

    /// Handle CREATED response from entry node
    ///
    /// Returns the EXTEND cell to send to the middle node (wrapped in RELAY)
    #[instrument(skip(self, cell), level = "info")]
    pub fn handle_created(&mut self, cell: CreatedCell) -> Result<ExtendCell> {
        info!(circuit_id = cell.circuit_id, "Handling CREATED response");

        let pending = self.pending_circuits.get_mut(&cell.circuit_id)
            .ok_or_else(|| {
                error!(circuit_id = cell.circuit_id, "Unknown pending circuit");
                RoutingError::Circuit(format!("Unknown pending circuit {}", cell.circuit_id))
            })?;

        if pending.hops_complete != 0 {
            error!(
                circuit_id = cell.circuit_id,
                hops_complete = pending.hops_complete,
                "Unexpected CREATED cell state"
            );
            return Err(RoutingError::Circuit("Unexpected CREATED cell state".into()));
        }

        // 1. Derive session key
        trace!("Deriving session key for entry hop");
        let secret = pending.ephemeral_secrets.first()
            .ok_or_else(|| {
                error!("No ephemeral secret for hop 0");
                RoutingError::Circuit("No ephemeral secret for hop 0".into())
            })?;

        let peer_public = x25519_dalek::PublicKey::from(cell.dh_public);
        let session_key = SessionKey::exchange(secret, &peer_public);

        pending.complete_hop(session_key);
        info!(circuit_id = cell.circuit_id, "Hop 1 (Entry) established");

        // 2. Prepare handshake for hop 2 (Middle)
        let middle_peer = pending.peer_ids[1];
        trace!(middle_peer = ?middle_peer, "Preparing handshake for middle hop");
        let (secret_2, public_2) = SessionKey::generate_ephemeral();
        pending.add_secret(secret_2);

        // 3. Create EXTEND cell for entry -> middle
        trace!("Creating EXTEND cell for middle hop");
        Ok(ExtendCell::new(middle_peer, *public_2.as_bytes()))
    }

    /// Handle EXTENDED response from middle/exit node
    ///
    /// Returns optional next EXTEND cell (if more hops needed), or the completed Circuit
    #[instrument(skip(self, cell), level = "info")]
    pub fn handle_extended(&mut self, circuit_id: u32, cell: ExtendedCell) -> Result<Option<(ExtendCell, Option<Circuit>)>> {
        info!(circuit_id, "Handling EXTENDED response");

        let pending = self.pending_circuits.get_mut(&circuit_id)
            .ok_or_else(|| {
                error!(circuit_id, "Unknown pending circuit");
                RoutingError::Circuit(format!("Unknown pending circuit {}", circuit_id))
            })?;

        // Current hop index (1 = middle, 2 = exit)
        let current_hop = pending.hops_complete;
        if current_hop >= 3 {
            error!(circuit_id, current_hop, "Circuit already complete");
            return Err(RoutingError::Circuit("Circuit already complete".into()));
        }

        // 1. Derive session key for this hop
        trace!(current_hop, "Deriving session key");
        let secret = &pending.ephemeral_secrets[current_hop];
        let peer_public = x25519_dalek::PublicKey::from(cell.dh_public);
        let session_key = SessionKey::exchange(secret, &peer_public);

        pending.complete_hop(session_key);
        info!(circuit_id, hop_num = current_hop + 1, "Hop established");

        // 2. Check if circuit is complete (3 hops)
        if pending.hops_complete == 3 {
            info!(circuit_id, "All 3 hops complete, finalizing circuit");

            // Finalize circuit
            let mut circuit = Circuit::new(circuit_id);

            // Move state from pending to circuit
            for i in 0..3 {
                circuit.add_hop(CircuitHop {
                    peer_id: pending.peer_ids[i],
                    session_key: pending.session_keys[i].clone(),
                    is_exit: i == 2,
                })?;
            }
            circuit.set_ready();

            // Cleanup pending
            self.pending_circuits.remove(&circuit_id);
            debug!(pending_count = self.pending_circuits.len(), "Pending circuit removed");

            // Add to completed circuits
            self.completed_circuits.push(circuit);
            info!(
                circuit_id,
                completed_count = self.completed_circuits.len(),
                "Circuit completed and ready"
            );

            return Ok(Some((
                // Dummy extend cell not used here
                ExtendCell::new([0u8; 32], [0u8; 32]),
                Some(circuit)
            )));
        }

        // 3. Prepare handshake for next hop (Exit)
        let next_peer = pending.peer_ids[pending.hops_complete];
        trace!(next_peer = ?next_peer, "Preparing handshake for next hop");
        let (secret_next, public_next) = SessionKey::generate_ephemeral();
        pending.add_secret(secret_next);

        let extend_cell = ExtendCell::new(next_peer, *public_next.as_bytes());
        trace!("EXTEND cell created for next hop");

        Ok(Some((extend_cell, None)))
    }
    /// Get the first hop (entry node) for a pending circuit
    pub fn get_first_hop(&self, circuit_id: CircuitId) -> Option<[u8; 32]> {
        self.pending_circuits.get(&circuit_id)
            .and_then(|p| p.peer_ids.first().copied())
    }
}
