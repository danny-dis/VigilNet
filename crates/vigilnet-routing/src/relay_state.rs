use vigilnet_crypto::SessionKey;
use crate::CircuitId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// State of a circuit passing through a relay
pub struct RelayCircuit {
    /// ID of the circuit on the incoming link
    pub incoming_circuit_id: CircuitId,
    /// Peer ID of the previous hop (incoming)
    pub previous_hop: Vec<u8>,
    /// ID of the circuit on the outgoing link (if extended)
    pub outgoing_circuit_id: Option<CircuitId>,
    /// Peer ID of the next hop (outgoing)
    pub next_hop: Option<Vec<u8>>,
    /// Shared session key for this hop (layer)
    pub session_key: SessionKey,
    /// When this circuit was created
    pub created_at: Instant,
    /// Number of bytes forwarded
    pub bytes_forwarded: u64,
    /// Number of cells forwarded
    pub cells_forwarded: u64,
}

impl RelayCircuit {
    pub fn new(incoming_id: CircuitId, previous_hop: Vec<u8>, session_key: SessionKey) -> Self {
        Self {
            incoming_circuit_id: incoming_id,
            previous_hop,
            outgoing_circuit_id: None,
            next_hop: None,
            session_key,
            created_at: Instant::now(),
            bytes_forwarded: 0,
            cells_forwarded: 0,
        }
    }

    /// Get the age of this circuit
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Add forwarded bytes
    pub fn add_bytes(&mut self, bytes: u64) {
        self.bytes_forwarded += bytes;
        self.cells_forwarded += 1;
    }
}

/// Manages all circuits passing through a relay
pub struct RelayState {
    /// All circuits by incoming circuit ID
    circuits: HashMap<CircuitId, RelayCircuit>,
    /// Maximum circuits to maintain
    max_circuits: usize,
    /// Circuit timeout
    circuit_timeout: Duration,
}

impl RelayState {
    /// Create new relay state
    pub fn new(max_circuits: usize) -> Self {
        Self {
            circuits: HashMap::new(),
            max_circuits,
            circuit_timeout: Duration::from_secs(3600),
        }
    }

    /// Add a new circuit
    pub fn add_circuit(&mut self, circuit: RelayCircuit) {
        if self.circuits.len() >= self.max_circuits {
            self.cleanup_old_circuits();
        }
        self.circuits.insert(circuit.incoming_circuit_id, circuit);
    }

    /// Get a circuit by incoming ID
    pub fn get_circuit(&self, incoming_id: CircuitId) -> Option<&RelayCircuit> {
        self.circuits.get(&incoming_id)
    }

    /// Get a circuit by incoming ID (mutable)
    pub fn get_circuit_mut(&mut self, incoming_id: CircuitId) -> Option<&mut RelayCircuit> {
        self.circuits.get_mut(&incoming_id)
    }

    /// Remove a circuit
    pub fn remove_circuit(&mut self, incoming_id: CircuitId) -> Option<RelayCircuit> {
        self.circuits.remove(&incoming_id)
    }

    /// Get all circuit IDs
    pub fn circuit_ids(&self) -> Vec<CircuitId> {
        self.circuits.keys().copied().collect()
    }

    /// Get the number of active circuits
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Clean up old circuits
    fn cleanup_old_circuits(&mut self) {
        let now = Instant::now();
        self.circuits.retain(|_, circuit| {
            now.duration_since(circuit.created_at) < self.circuit_timeout
        });
    }

    /// Set circuit timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.circuit_timeout = timeout;
        self
    }
}

impl Default for RelayState {
    fn default() -> Self {
        Self::new(1000)
    }
}
