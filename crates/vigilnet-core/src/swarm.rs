//! VigilNet Swarm
//!
//! Manages the libp2p swarm and event loop.

use crate::config::{AgentConfig, Config};
use crate::error::{Error, Result};
use crate::swarm::{SwarmCommand, SwarmNotification};
use libp2p::{
    identity::Keypair,
    noise, tcp, yamux,
    swarm::{Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use vigilnet_discovery::{
    E2EESessionManager, VigilNetBehaviour, VigilNetBehaviourEvent, VigilNetEvent,
    map_behaviour_event,
};
use vigilnet_routing::{
    path::PathSelector, policy::ExitPolicy, Circuit, CircuitBuilder, Relay, RelayCircuit,
};
use vigilnet_crypto::keys::StaticSecret;
use vigilnet_crypto::onion::{
    BeginCell, CircuitCell, ConnectedCell, CreateCell, ExtendedCell, RelayCell,
};

struct InternalStreamEvent {
    circuit_id: u32,
    data: Vec<u8>,
    closed: bool,
}

/// The swarm manager
pub struct VigilNetSwarm {
    /// The libp2p swarm
    swarm: Swarm<VigilNetBehaviour>,
    /// Connected peers
    connected_peers: HashMap<PeerId, Vec<Multiaddr>>,
    /// Circuit builder
    circuit_builder: CircuitBuilder,
    /// Relay logic
    relay: Relay,
    /// E2EE Session Manager
    e2ee: Option<E2EESessionManager>,
    /// Our static Diffie-Hellman secret (for relaying)
    static_secret: StaticSecret,
    /// Active circuits where we act as a relay (CircuitId -> (PeerId, RelayCircuit))
    relay_circuits: HashMap<u32, (PeerId, RelayCircuit)>,
    /// Active circuits where we are the origin (CircuitId -> Circuit)
    active_circuits: HashMap<u32, Circuit>,
    /// First hop for each active circuit (CircuitId -> PeerId bytes)
    circuit_first_hops: HashMap<u32, [u8; 32]>,
    /// Map from (Outgoing Peer, Outgoing CircuitId) -> (Incoming Peer, Incoming CircuitId)
    outbound_circuit_map: HashMap<(PeerId, u32), (PeerId, u32)>,
    /// Pending circuit requests (CircuitId -> Sender)
    pending_circuit_requests: HashMap<u32, mpsc::Sender<Result<u32>>>,
    /// Command receiver
    command_rx: mpsc::Receiver<SwarmCommand>,
    /// Notification sender
    notify_tx: mpsc::Sender<SwarmNotification>,
    /// Exit Policy
    exit_policy: ExitPolicy,
    /// Outgoing TCP streams (CircuitId -> WriteHalf)
    outgoing_streams: HashMap<u32, tokio::net::tcp::OwnedWriteHalf>,
    /// Receiver for internal stream events
    stream_data_rx: mpsc::Receiver<InternalStreamEvent>,
    /// Sender for internal stream events (to clone for tasks)
    stream_data_tx: mpsc::Sender<InternalStreamEvent>,
    /// Local peer ID
    local_peer_id: PeerId,
    /// E2EE enabled
    e2ee_enabled: bool,
    /// Agent config
    agent_config: AgentConfig,
}

impl VigilNetSwarm {
    /// Create a new swarm
    pub fn new(
        config: &Config,
        command_rx: mpsc::Receiver<SwarmCommand>,
        notify_tx: mpsc::Sender<SwarmNotification>,
    ) -> Result<Self> {
        // Generate or load keypair
        let local_key = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer ID: {}", local_peer_id);

        // Generate static DH secret for relaying
        let (static_secret, _) = vigilnet_crypto::SessionKey::generate_static();

        // Initialize E2EE session manager if enabled
        let e2ee = if config.agent.enable_e2ee {
            let identity_key = rand::random::<[u8; 32]>();
            let session_key = rand::random::<[u8; 32]>();
            Some(E2EESessionManager::new(
                local_peer_id,
                identity_key,
                session_key,
            ))
        } else {
            None
        };

        // Create swarm
        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| Error::Network(format!("TCP setup failed: {}", e)))?
            .with_quic()
            .with_behaviour(|key| {
                VigilNetBehaviour::new(local_peer_id, key)
            })
            .map_err(|e| Error::Network(format!("Behaviour setup failed: {}", e)))?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build();

        // Initialize circuit builder - map config PathStrategy to routing PathStrategy
        let routing_strategy = match config.privacy.path_strategy {
            crate::config::PathStrategy::Random => vigilnet_routing::path::PathStrategy::Random,
            crate::config::PathStrategy::LowestLatency => vigilnet_routing::path::PathStrategy::LowLatency,
            crate::config::PathStrategy::Hybrid => vigilnet_routing::path::PathStrategy::Hybrid,
            crate::config::PathStrategy::Trusted => vigilnet_routing::path::PathStrategy::ReputationWeighted,
        };
        let path_selector = PathSelector::new()
            .with_strategy(routing_strategy);
        let circuit_builder = CircuitBuilder::new(path_selector);

        // Initialize relay
        let relay_id = local_peer_id.to_bytes();
        let relay = Relay::new(relay_id);

        let (stream_data_tx, stream_data_rx) = mpsc::channel(64);

        Ok(Self {
            swarm,
            connected_peers: HashMap::new(),
            circuit_builder,
            relay,
            e2ee,
            static_secret,
            relay_circuits: HashMap::new(),
            active_circuits: HashMap::new(),
            circuit_first_hops: HashMap::new(),
            outbound_circuit_map: HashMap::new(),
            pending_circuit_requests: HashMap::new(),
            command_rx,
            notify_tx,
            exit_policy: ExitPolicy::default(),
            outgoing_streams: HashMap::new(),
            stream_data_rx,
            stream_data_tx,
            local_peer_id,
            e2ee_enabled: config.agent.enable_e2ee,
            agent_config: config.agent.clone(),
        })
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Get E2EE session manager
    pub fn e2ee(&self) -> Option<&E2EESessionManager> {
        self.e2ee.as_ref()
    }

    /// Check if E2EE is enabled
    pub fn is_e2ee_enabled(&self) -> bool {
        self.e2ee_enabled
    }

    /// Get agent config
    pub fn agent_config(&self) -> &AgentConfig {
        &self.agent_config
    }

    /// Start listening on configured addresses
    pub async fn start_listening(&mut self, config: &Config) -> Result<()> {
        for addr_str in &config.network.listen_addrs {
            let addr: Multiaddr = addr_str
                .parse()
                .map_err(|e| Error::Config(format!("Invalid address {}: {}", addr_str, e)))?;
            
            self.swarm
                .listen_on(addr.clone())
                .map_err(|e| Error::Network(format!("Listen failed on {}: {}", addr, e)))?;
            
            info!("Listening on {}", addr);
        }
        Ok(())
    }

    /// Run the swarm event loop
    pub async fn run(mut self) {
        info!("Starting swarm event loop");

        // Bootstrap Kademlia
        if let Err(e) = self.swarm.behaviour_mut().bootstrap() {
            warn!("Kademlia bootstrap failed: {}", e);
        }

        loop {
            tokio::select! {
                // Handle swarm events
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }
                
                // Handle commands from Node
                Some(cmd) = self.command_rx.recv() => {
                    match cmd {
                        SwarmCommand::GetPeers(tx) => {
                            let peers: Vec<_> = self.connected_peers.keys().cloned().collect();
                            let _ = tx.send(peers).await;
                        }
                        SwarmCommand::AddBootstrapPeer(peer_id, addr) => {
                            self.swarm.behaviour_mut().add_address(&peer_id, addr);
                        }
                        SwarmCommand::Dial(addr) => {
                            if let Err(e) = self.swarm.dial(addr.clone()) {
                                error!("Failed to dial {}: {}", addr, e);
                            }
                        }
                        SwarmCommand::BuildCircuit(tx) => {
                            match self.circuit_builder.init_circuit() {
                                Ok((circuit_id, entry_peer, create_cell)) => {
                                    self.pending_circuit_requests.insert(circuit_id, tx);
                                    
                                    // Send CREATE cell
                                    let cell = CircuitCell::create(&create_cell);
                                    if let Ok(entry_peer_id) = PeerId::from_bytes(&entry_peer) {
                                        let request_id = self.swarm.behaviour_mut().circuit.send_request(
                                            &entry_peer_id,
                                            cell
                                        );
                                        info!("Started building circuit {}, request {:?}", circuit_id, request_id);
                                    } else {
                                        let _ = tx.send(Err(Error::Network("Invalid entry peer ID".into()))).await;
                                    }
                                }
                                Err(e) => {
                                    let _ = tx.send(Err(Error::Network(format!("Failed to init circuit: {}", e)))).await;
                                }
                            }
                        }
                        SwarmCommand::SendData(circuit_id, data, tx) => {
                            // Get first hop from our stored mapping
                            if let Some(first_hop) = self.circuit_first_hops.get(&circuit_id) {
                                let relay_cell = RelayCell::data(0, data);
                                let cell = CircuitCell::relay(circuit_id, relay_cell.to_bytes());
                                
                                if let Ok(peer) = PeerId::from_bytes(first_hop) {
                                    let _ = self.swarm.behaviour_mut().circuit.send_request(&peer, cell);
                                    let _ = tx.send(Ok(())).await;
                                } else {
                                    let _ = tx.send(Err(Error::Internal("Invalid peer ID in circuit".into()))).await;
                                }
                            } else {
                                let _ = tx.send(Err(Error::Network("Circuit not found".into()))).await;
                            }
                        }
                        SwarmCommand::Shutdown => {
                            info!("Swarm shutdown requested");
                            break;
                        }
                    }
                }

                // Handle internal stream events (Reverse path: Exit -> Origin)
                Some(event) = self.stream_data_rx.recv() => {
                    if let Some((peer_id, circuit)) = self.relay_circuits.get(&event.circuit_id) {
                         if !event.closed {
                             // Encrypt and send RELAY_DATA
                             let relay_cell = RelayCell::data(0, event.data);
                             
                             if let Ok(encrypted) = vigilnet_crypto::aead::encrypt(
                                circuit.session_key.as_bytes(), 
                                &relay_cell.to_bytes()
                             ) {
                                let cell = CircuitCell::relay(event.circuit_id, encrypted);
                                let _ = self.swarm.behaviour_mut().circuit.send_request(peer_id, cell);
                             }
                         }
                    }
                }
            }
        }

        info!("Swarm event loop ended");
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<VigilNetBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                let _ = self.notify_tx.send(SwarmNotification::Listening(address)).await;
            }
            SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } => {
                info!("Connected to {}", peer_id);
                self.connected_peers.insert(peer_id, vec![]);
                let _ = self.notify_tx.send(SwarmNotification::PeerConnected(peer_id)).await;
            }
            SwarmEvent::ConnectionClosed { peer_id, connection_id, .. } => {
                info!("Disconnected from {}", peer_id);
                self.connected_peers.remove(&peer_id);
                let _ = self.notify_tx.send(SwarmNotification::PeerDisconnected(peer_id)).await;
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                let session_mgr = self.e2ee.as_ref();
                if let Some(vigilnet_event) = map_behaviour_event(behaviour_event, session_mgr) {
                    self.handle_vigilnet_event(vigilnet_event).await;
                }
            }
            SwarmEvent::IncomingConnection { local_addr, send_back_addr, .. } => {
                debug!("Incoming connection from {} on {}", send_back_addr, local_addr);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer) = peer_id {
                    warn!("Failed to connect to {}: {}", peer, error);
                }
            }
            _ => {}
        }
    }

    async fn handle_vigilnet_event(&mut self, event: VigilNetEvent) {
        match event {
            VigilNetEvent::MdnsPeerDiscovered(peer_id, addrs) => {
                info!("mDNS discovered peer: {} at {:?}", peer_id, addrs);
                for addr in addrs {
                    self.swarm.behaviour_mut().add_address(&peer_id, addr.clone());
                    if let Some(addrs) = self.connected_peers.get_mut(&peer_id) {
                        addrs.push(addr);
                    } else {
                        self.connected_peers.insert(peer_id, vec![addr]);
                    }
                    if !self.connected_peers.contains_key(&peer_id) {
                        if let Err(e) = self.swarm.dial(addr) {
                            debug!("Failed to dial mDNS peer: {}", e);
                        }
                    }
                }
            }
            VigilNetEvent::MdnsPeerExpired(peer_id) => {
                debug!("mDNS peer expired: {}", peer_id);
            }
            VigilNetEvent::KademliaPeerDiscovered(peer_id) => {
                debug!("Kademlia discovered peer: {}", peer_id);
            }
            VigilNetEvent::KademliaRoutingUpdated { peer, addresses } => {
                debug!("Kademlia routing updated: {} with {} addresses", peer, addresses.len());
            }
            VigilNetEvent::IdentifyReceived { peer_id, info } => {
                debug!("Identify from {}: {} protocols", peer_id, info.protocols.len());
                for addr in info.listen_addrs {
                    self.swarm.behaviour_mut().add_address(&peer_id, addr);
                }
            }
            VigilNetEvent::GossipMessage { peer_id, topic, data } => {
                debug!("Gossip from {}: {} bytes", peer_id, data.len());
            }
            VigilNetEvent::GossipMessageDecrypted { peer_id, topic, plaintext } => {
                info!("Decrypted gossip from {} on {}: {} bytes", peer_id, topic, plaintext.len());
            }
            VigilNetEvent::CircuitMessage { peer_id, message, response_channel } => {
                debug!("Received circuit message from {}", peer_id);
                // Handle circuit protocol message - message is Vec<u8>
                // Need to parse as CircuitCell
                if let Ok(cell) = CircuitCell::from_bytes(&message) {
                    match cell.cell_type {
                        vigilnet_crypto::onion::CellType::Create => {
                            if let Ok(create_cell) = CreateCell::from_bytes(&message) {
                                match self.relay.handle_create(&create_cell, &self.static_secret) {
                                    Ok((created_cell, session_key)) => {
                                        let relay_circuit = RelayCircuit::new(
                                            cell.circuit_id,
                                            peer_id.to_bytes(),
                                            session_key
                                        );
                                        self.relay_circuits.insert(cell.circuit_id, (peer_id, relay_circuit));

                                        let response = CircuitCell::created(&created_cell);
                                        let _ = self.swarm.behaviour_mut().circuit.send_response(response_channel, response);
                                        info!("Handled CREATE from {}, sent CREATED", peer_id);
                                    }
                                    Err(e) => {
                                        warn!("Failed to handle CREATE from {}: {}", peer_id, e);
                                    }
                                }
                            }
                        }
                        vigilnet_crypto::onion::CellType::Relay => {
                            if let Some((_, circuit)) = self.relay_circuits.get_mut(&cell.circuit_id) {
                                if let Ok(decrypted) = self.relay.decrypt_cell(&message, &circuit.session_key) {
                                    if let Ok(relay_cell) = RelayCell::from_bytes(&decrypted) {
                                        match relay_cell.command {
                                            vigilnet_crypto::onion::RelayCommand::Extend => {
                                                if let Ok(extend_cell) = vigilnet_crypto::onion::ExtendCell::from_bytes(&relay_cell.data) {
                                                    if let Ok(next_hop_peer) = PeerId::from_bytes(&extend_cell.next_hop) {
                                                        let next_circuit_id = rand::random::<u32>();
                                                        circuit.outgoing_circuit_id = Some(next_circuit_id);
                                                        circuit.next_hop = Some(extend_cell.next_hop.to_vec());
                                                        
                                                        self.outbound_circuit_map.insert(
                                                            (next_hop_peer, next_circuit_id), 
                                                            (peer_id, cell.circuit_id)
                                                        );
                                                        
                                                        let create_cell = CreateCell {
                                                            circuit_id: next_circuit_id,
                                                            dh_public: extend_cell.dh_public
                                                        };
                                                        let cell = CircuitCell::create(&create_cell);
                                                        
                                                        let _ = self.swarm.behaviour_mut().circuit.send_request(&next_hop_peer, cell);
                                                        info!("Relaying EXTEND from {} to {}", peer_id, next_hop_peer);
                                                    }
                                                }
                                            }
                                            vigilnet_crypto::onion::RelayCommand::Data => {
                                                if let Some(next_hop_bytes) = &circuit.next_hop {
                                                    if let Some(next_circuit_id) = circuit.outgoing_circuit_id {
                                                        if let Ok(next_peer) = PeerId::from_bytes(next_hop_bytes) {
                                                            let forwarded_cell = CircuitCell::relay(next_circuit_id, relay_cell.data);
                                                            let _ = self.swarm.behaviour_mut().circuit.send_request(&next_peer, forwarded_cell);
                                                        }
                                                    }
                                                } else {
                                                    if let Some(stream) = self.outgoing_streams.get_mut(&cell.circuit_id) {
                                                        let _ = stream.write_all(&relay_cell.data).await;
                                                    }
                                                }
                                            }
                                            vigilnet_crypto::onion::RelayCommand::Begin => {
                                                if let Ok(begin_cell) = BeginCell::from_bytes(&relay_cell.data) {
                                                    let port = begin_cell.address.split(':').last().and_then(|p| p.parse().ok()).unwrap_or(0);
                                                    
                                                    if self.exit_policy.check(&begin_cell.address, port) == vigilnet_routing::policy::PolicyAction::Allow {
                                                        info!("Exit Allowed: Connecting to {}", begin_cell.address);
                                                        
                                                        let tx = self.stream_data_tx.clone();
                                                        let circuit_id = cell.circuit_id;
                                                        
                                                        match tokio::net::TcpStream::connect(&begin_cell.address).await {
                                                            Ok(stream) => {
                                                                let (mut rd, wr) = stream.into_split();
                                                                self.outgoing_streams.insert(cell.circuit_id, wr);
                                                                
                                                                tokio::spawn(async move {
                                                                    let mut buf = [0u8; 4096];
                                                                    loop {
                                                                        match rd.read(&mut buf).await {
                                                                            Ok(0) => break,
                                                                            Ok(n) => {
                                                                                let _ = tx.send(InternalStreamEvent {
                                                                                    circuit_id,
                                                                                    data: buf[0..n].to_vec(),
                                                                                    closed: false,
                                                                                }).await;
                                                                            }
                                                                            Err(_) => break,
                                                                        }
                                                                    }
                                                                });
                                                                
                                                                let connected = ConnectedCell::new("0.0.0.0");
                                                                let relay_resp = RelayCell::connected(0, &connected);
                                                                if let Ok(encrypted) = vigilnet_crypto::aead::encrypt(circuit.session_key.as_bytes(), &relay_resp.to_bytes()) {
                                                                    let cell = CircuitCell::relay(cell.circuit_id, encrypted);
                                                                    let _ = self.swarm.behaviour_mut().circuit.send_request(&peer_id, cell);
                                                                }
                                                            }
                                                            Err(e) => {
                                                                warn!("Failed to connect to {}: {}", begin_cell.address, e);
                                                            }
                                                        }
                                                    } else {
                                                        warn!("Exit Policy Denied: {}", begin_cell.address);
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            VigilNetEvent::CircuitResponse { request_id: _, message } => {
                if let Ok(cell) = CircuitCell::from_bytes(&message) {
                    match cell.cell_type {
                        vigilnet_crypto::onion::CellType::Created => {
                            if let Some(tx) = self.pending_circuit_requests.remove(&cell.circuit_id) {
                                if let Ok(created) = vigilnet_crypto::onion::CreatedCell::from_bytes(&message) {
                                    match self.circuit_builder.handle_created(created) {
                                        Ok(extend_cell) => {
                                            if let Some(first_hop) = self.circuit_builder.get_first_hop(cell.circuit_id) {
                                                if let Ok(peer) = PeerId::from_bytes(&first_hop) {
                                                    let relay_cell = RelayCell::extend(&extend_cell);
                                                    let cell = CircuitCell::relay(cell.circuit_id, relay_cell.to_bytes());
                                                    let _ = self.swarm.behaviour_mut().circuit.send_request(&peer, cell);
                                                    self.pending_circuit_requests.insert(cell.circuit_id, tx);
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            // Circuit is ready - store the first hop
                                            if let Some(first_hop) = self.circuit_builder.get_first_hop(cell.circuit_id) {
                                                self.circuit_first_hops.insert(cell.circuit_id, first_hop);
                                            }
                                            let _ = tx.send(Ok(cell.circuit_id)).await;
                                        }
                                    }
                                }
                            } else if let Some((prev_peer, prev_circuit_id)) = self.outbound_circuit_map.get(&(peer_id, cell.circuit_id)) {
                                if let Ok(created) = vigilnet_crypto::onion::CreatedCell::from_bytes(&message) {
                                    let extended = ExtendedCell {
                                        dh_public: created.dh_public
                                    };
                                    
                                    if let Some((_, circuit)) = self.relay_circuits.get(prev_circuit_id) {
                                        let relay_cell = RelayCell::extended(&extended);
                                        
                                        if let Ok(encrypted) = vigilnet_crypto::aead::encrypt(
                                            circuit.session_key.as_bytes(), 
                                            &relay_cell.to_bytes()
                                        ) {
                                            let cell = CircuitCell::relay(*prev_circuit_id, encrypted);
                                            let _ = self.swarm.behaviour_mut().circuit.send_request(prev_peer, cell);
                                            info!("Relayed CREATED/EXTENDED back to {}", prev_peer);
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            VigilNetEvent::SessionEstablished(peer_id) => {
                info!("E2EE session established with {}", peer_id);
            }
            VigilNetEvent::SessionVerifyFailed(peer_id) => {
                warn!("E2EE session verification failed with {}", peer_id);
            }
            _ => {}
        }
    }
}
