//! VigilNet Swarm
//!
//! Manages the libp2p swarm and event loop.

use libp2p::{
    identity::Keypair,
    noise, tcp, yamux,
    swarm::{Swarm, SwarmEvent},
    Multiaddr, PeerId,
};
use std::collections::HashSet;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use vigilnet_routing::{Circuit, CircuitBuilder, PathSelector, policy::ExitPolicy};
use vigilnet_crypto::onion::{CircuitCell, CreateCell, ExtendedCell, BeginCell, ConnectedCell, RelayCommand};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Swarm command sent from Node to the swarm task
#[derive(Debug)]
pub enum SwarmCommand {
    /// Get list of connected peers
    GetPeers(mpsc::Sender<Vec<PeerId>>),
    /// Add a bootstrap peer
    AddBootstrapPeer(PeerId, Multiaddr),
    /// Dial a peer
    Dial(Multiaddr),
    /// Build a new circuit
    BuildCircuit(mpsc::Sender<Result<u32>>),
    /// Send data over a circuit
    SendData(u32, Vec<u8>, mpsc::Sender<Result<()>>),
    /// Shutdown the swarm
    Shutdown,
}

/// Events from the swarm sent to the Node
#[derive(Debug, Clone)]
pub enum SwarmNotification {
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// Listening on address
    Listening(Multiaddr),
    /// Circuit built successfully
    CircuitBuilt(u32),
    /// Error occurred
    Error(String),
}

/// Internal events from streams
#[derive(Debug)]
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
    connected_peers: HashSet<PeerId>,
    /// Circuit builder
    circuit_builder: CircuitBuilder,
    /// Relay logic
    relay: vigilnet_routing::Relay,
    /// Our static Diffie-Hellman secret (for relaying)
    static_secret: vigilnet_crypto::keys::StaticSecret,
    /// Active circuits where we act as a relay (Incoming Peer, Incoming CircuitId) -> State
    relay_circuits: std::collections::HashMap<(PeerId, u32), vigilnet_routing::RelayCircuit>,
    /// Active circuits where we are the origin (CircuitId -> Circuit)
    active_circuits: std::collections::HashMap<u32, Circuit>,
    /// Map from (Outgoing Peer, Outgoing CircuitId) -> (Incoming Peer, Incoming CircuitId)
    outbound_circuit_map: std::collections::HashMap<(PeerId, u32), (PeerId, u32)>,
    /// Pending circuit requests (CircuitId -> Sender)
    pending_circuit_requests: std::collections::HashMap<u32, mpsc::Sender<Result<u32>>>,
    /// Command receiver
    command_rx: mpsc::Receiver<SwarmCommand>,
    /// Notification sender
    notify_tx: mpsc::Sender<SwarmNotification>,
    /// Exit Policy
    exit_policy: ExitPolicy,
    /// Outgoing TCP streams (CircuitId -> WriteHalf)
    outgoing_streams: std::collections::HashMap<u32, OwnedWriteHalf>,
    /// Receiver for internal stream events
    stream_data_rx: mpsc::Receiver<InternalStreamEvent>,
    /// Sender for internal stream events (to clone for tasks)
    stream_data_tx: mpsc::Sender<InternalStreamEvent>,
}

impl VigilNetSwarm {
    /// Create a new swarm
    pub fn new(
        config: &Config,
        command_rx: mpsc::Receiver<SwarmCommand>,
        notify_tx: mpsc::Sender<SwarmNotification>,
    ) -> Result<Self> {
        // ... (existing code) ...
        // Generate or load keypair
        let local_key = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        info!("Local peer ID: {}", local_peer_id);

        // Generate static DH secret for relaying
        let (static_secret, _) = vigilnet_crypto::SessionKey::generate_static();

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

        // Initialize circuit builder
        let path_selector = PathSelector::new()
            .with_strategy(config.privacy.path_strategy);
        let circuit_builder = CircuitBuilder::new(path_selector);

        // Initialize relay
        let relay_id = [0u8; 32]; // Placeholder
        let relay = vigilnet_routing::Relay::new(relay_id);

        let (stream_data_tx, stream_data_rx) = mpsc::channel(64);

        Ok(Self {
            swarm,
            connected_peers: HashSet::new(),
            circuit_builder,
            relay,
            static_secret,
            relay_circuits: std::collections::HashMap::new(),
            active_circuits: std::collections::HashMap::new(),
            outbound_circuit_map: std::collections::HashMap::new(),
            pending_circuit_requests: std::collections::HashMap::new(),
            command_rx,
            notify_tx,
            exit_policy: ExitPolicy::default(),
            outgoing_streams: std::collections::HashMap::new(),
            stream_data_rx,
            stream_data_tx,
        })
    }
    
    // ... (rest of methods until handle_vigilnet_event) ...

    async fn handle_vigilnet_event(&mut self, event: VigilNetEvent) {
        match event {
            // ... (existing match arms) ...
            VigilNetEvent::MdnsPeerDiscovered(peer_id, addrs) => {
                 // ...
                 info!("mDNS discovered peer: {} at {:?}", peer_id, addrs);
                for addr in addrs {
                    self.swarm.behaviour_mut().add_address(&peer_id, addr.clone());
                    if !self.connected_peers.contains(&peer_id) {
                        let _ = self.swarm.dial(addr);
                    }
                }
            }
             VigilNetEvent::MdnsPeerExpired(peer_id) => {
                debug!("mDNS peer expired: {}", peer_id);
            }
            VigilNetEvent::KademliaPeerDiscovered(peer_id) => {
                debug!("Kademlia discovered peer: {}", peer_id);
            }
            VigilNetEvent::IdentifyReceived { peer_id, info } => {
                debug!("Identify from {}: {} protocols", peer_id, info.protocols.len());
                for addr in info.listen_addrs {
                    self.swarm.behaviour_mut().add_address(&peer_id, addr);
                }
            }
            VigilNetEvent::CircuitMessage { peer_id, message, response_channel } => {
                debug!("Received circuit message from {}", peer_id);
                match message.cell_type {
                    vigilnet_crypto::onion::CellType::Create => {
                        if let Ok(create_cell) = vigilnet_crypto::onion::CreateCell::from_bytes(&message.payload) {
                             match self.relay.handle_create(&create_cell, &self.static_secret) {
                                Ok((created_cell, session_key)) => {
                                    // Store circuit state
                                    let relay_circuit = vigilnet_routing::RelayCircuit::new(
                                        message.circuit_id,
                                        peer_id.to_bytes(),
                                        session_key
                                    );
                                    self.relay_circuits.insert((peer_id, message.circuit_id), relay_circuit);

                                    // Send CREATED response
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
                        // Check if we have a circuit for this
                        if let Some(circuit) = self.relay_circuits.get_mut(&(peer_id, message.circuit_id)) {
                             // Decrypt payload
                             match self.relay.decrypt_cell(&message.payload, &circuit.session_key) {
                                 Ok(decrypted) => {
                                     // Parse RelayCell
                                     if let Ok(relay_cell) = vigilnet_crypto::onion::RelayCell::from_bytes(&decrypted) {
                                         match relay_cell.command {
                                             vigilnet_crypto::onion::RelayCommand::Extend => {
                                                 // TODO: Implement Extend
                                                 info!("Received Relay EXTEND command - implementation pending");
                                             }
                                             vigilnet_crypto::onion::RelayCommand::Data => {
                                                 // Check if we are exit or need to forward
                                                 if circuit.next_hop.is_some() {
                                                     // Forward to next hop
                                                     // We need to re-encrypt? No, we just decrypted one layer.
                                                     // The decrypted payload IS the cell for the next hop.
                                                     // We need to wrap it in a CircuitCell and send it.
                                                     // But wait, message.payload is the Encrypted onion.
                                                     // decrypt_cell peels ONE layer.
                                                     // The result `decrypted` IS the payload for the next hop?
                                                     // No, if I am a relay, `decrypted` is the RelayCell destined for ME or NEXT.
                                                     // If it's for NEXT, it looks like an encrypted blob to me?
                                                     // In basic O-R, the client encrypts layers: Enc(Enc(Enc(M))).
                                                     // I decrypt: Dec(Enc(Enc(Enc(M)))) = Enc(Enc(M)).
                                                     // So `decrypted` bytes ARE the payload for next hop.
                                                     // But `RelayCell::from_bytes` tries to parse it as a struct.
                                                     // If it's encrypted, it won't parse validly as RelayCell... usually.
                                                     // UNLESS: Relay headers are plaintext?
                                                     // In Tor, the header is encrypted too.
                                                     // If I peel a layer, and it's NOT for me, I should relay it.
                                                     // How do I know if it's for me?
                                                     // In Tor, you check for a valid digest/recognized field.
                                                     // Here we simplified.
                                                     
                                                     // For this prototype: 
                                                     // If we are NOT the exit (implied by having a next hop?), we just forward `decrypted`.
                                                     // But we need to define valid/recognized.
                                                     
                                                     // Simplified logic: strict 3-hop.
                                                     // If I have a `next_hop`, I forward.
                                                 }
                                             }
                                             _ => {}
                                         }
                                     }
                                 }
                                 Err(e) => warn!("Failed to decrypt relay cell from {}: {}", peer_id, e),
                             }
                        } else {
                            warn!("Received RELAY cell for unknown circuit {} from {}", message.circuit_id, peer_id);
                        }
                    }
                    _ => {}
                }
            }
            // ... (existing response handling) ...
        }
    }

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
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
                            let peers: Vec<_> = self.connected_peers.iter().cloned().collect();
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
                                    let request_id = self.swarm.behaviour_mut().circuit.send_request(
                                        &PeerId::from_bytes(&entry_peer).unwrap(),
                                        cell
                                    );
                                    info!("Started building circuit {}, request {:?}", circuit_id, request_id);
                                }
                                Err(e) => {
                                    let _ = tx.send(Err(Error::Network(format!("Failed to init circuit: {}", e)))).await;
                                }
                            }
                        }
                        SwarmCommand::SendData(circuit_id, data, tx) => {
                            if let Some(circuit) = self.active_circuits.get(&circuit_id) {
                                // 1. Encrypt data (3 layers) - simplified for prototype: just wrap
                                // In real impl, we'd loop through hops and encrypt.
                                // let encrypted = circuit.encrypt(&data); 
                                // For now, we wrap in RelayCell(Data) and send to first hop
                                
                                // Get first hop
                                if let Some(first_hop) = circuit.hops.first() {
                                    // TODO: Encrypt properly
                                    let relay_cell = vigilnet_crypto::onion::RelayCell::data(0, data); // StreamID 0
                                    let cell = CircuitCell::relay(circuit_id, relay_cell.to_bytes());
                                    
                                     // PeerId from [u8;32]
                                    if let Ok(peer) = PeerId::from_bytes(&first_hop.peer_id) {
                                         let _ = self.swarm.behaviour_mut().circuit.send_request(&peer, cell);
                                         let _ = tx.send(Ok(())).await;
                                    } else {
                                        let _ = tx.send(Err(Error::Internal("Invalid peer ID in circuit".into()))).await;
                                    }
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
                    if let Some(((peer_id, _), circuit)) = self.relay_circuits.iter().find(|((_, cid), _)| *cid == event.circuit_id) {
                         if !event.closed {
                             // Encrypt and send RELAY_DATA
                             let relay_cell = vigilnet_crypto::onion::RelayCell::data(0, event.data);
                             
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

    async fn handle_swarm_event(&mut self, event: SwarmEvent<vigilnet_discovery::VigilNetBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                let _ = self.notify_tx.send(SwarmNotification::Listening(address)).await;
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to {}", peer_id);
                self.connected_peers.insert(peer_id);
                let _ = self.notify_tx.send(SwarmNotification::PeerConnected(peer_id)).await;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from {}", peer_id);
                self.connected_peers.remove(&peer_id);
                let _ = self.notify_tx.send(SwarmNotification::PeerDisconnected(peer_id)).await;
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                if let Some(vigilnet_event) = map_behaviour_event(behaviour_event) {
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
                    // Try to dial the discovered peer
                    if !self.connected_peers.contains(&peer_id) {
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
                // In a real implementation, we would add this peer to PathSelector
            }
            VigilNetEvent::IdentifyReceived { peer_id, info } => {
                debug!("Identify from {}: {} protocols", peer_id, info.protocols.len());
                for addr in info.listen_addrs {
                    self.swarm.behaviour_mut().add_address(&peer_id, addr);
                }
            }
            VigilNetEvent::CircuitMessage { peer_id, message, response_channel } => {
                debug!("Received circuit message from {}", peer_id);
                match message.cell_type {
                    vigilnet_crypto::onion::CellType::Create => {
                        if let Ok(create_cell) = vigilnet_crypto::onion::CreateCell::from_bytes(&message.payload) {
                             match self.relay.handle_create(&create_cell, &self.static_secret) {
                                Ok((created_cell, session_key)) => {
                                    // Store circuit state
                                    let relay_circuit = vigilnet_routing::RelayCircuit::new(
                                        message.circuit_id,
                                        peer_id.to_bytes(),
                                        session_key
                                    );
                                    self.relay_circuits.insert((peer_id, message.circuit_id), relay_circuit);

                                    // Send CREATED response
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
                        // Check if we have a circuit for this
                        if let Some(circuit) = self.relay_circuits.get_mut(&(peer_id, message.circuit_id)) {
                             // Decrypt payload
                             match self.relay.decrypt_cell(&message.payload, &circuit.session_key) {
                                 Ok(decrypted) => {
                                     // Parse RelayCell
                                     if let Ok(relay_cell) = vigilnet_crypto::onion::RelayCell::from_bytes(&decrypted) {
                                         match relay_cell.command {
                                             vigilnet_crypto::onion::RelayCommand::Extend => {
                                                 if let Ok(extend_cell) = vigilnet_crypto::onion::ExtendCell::from_bytes(&relay_cell.data) {
                                                     // 1. Parse next hop
                                                     if let Ok(next_hop_peer) = PeerId::from_bytes(&extend_cell.next_hop) {
                                                         // 2. Generate new circuit ID for outgoing link
                                                         let next_circuit_id = rand::random::<u32>();
                                                         
                                                         // 3. Store in circuit state
                                                         circuit.outgoing_circuit_id = Some(next_circuit_id);
                                                         circuit.next_hop = Some(extend_cell.next_hop.to_vec());
                                                         
                                                         // 4. Update index map
                                                         self.outbound_circuit_map.insert(
                                                             (next_hop_peer, next_circuit_id), 
                                                             (peer_id, message.circuit_id)
                                                         );
                                                         
                                                         // 5. Send CREATE to next hop
                                                         let create_cell = vigilnet_crypto::onion::CreateCell {
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
                                                 // Check if we are exit or need to forward
                                                 if let Some(next_hop_bytes) = &circuit.next_hop {
                                                     // Forwarding logic (existing)
                                                     if let Some(next_circuit_id) = circuit.outgoing_circuit_id {
                                                         if let Ok(next_peer) = PeerId::from_bytes(next_hop_bytes) {
                                                              // Forward to next hop
                                                              let forwarded_cell = CircuitCell::relay(next_circuit_id, relay_cell.data);
                                                              let _ = self.swarm.behaviour_mut().circuit.send_request(&next_peer, forwarded_cell);
                                                         }
                                                     }
                                                 } else {
                                                     // We are the Exit! Write to outgoing stream.
                                                     if let Some(stream) = self.outgoing_streams.get_mut(&message.circuit_id) {
                                                         let _ = stream.write_all(&relay_cell.data).await;
                                                     }
                                                 }
                                             }
                                             vigilnet_crypto::onion::RelayCommand::Begin => {
                                                // Handle BEGIN (Open TCP connection)
                                                if let Ok(begin_cell) = BeginCell::from_bytes(&relay_cell.data) {
                                                    // 1. Check Policy
                                                    // Parse port from address string (e.g., "google.com:80")
                                                    let port = begin_cell.address.split(':').last().and_then(|p| p.parse().ok()).unwrap_or(0);
                                                    
                                                    if self.exit_policy.check(&begin_cell.address, port) == vigilnet_routing::policy::PolicyAction::Allow {
                                                        info!("Exit Allowed: Connecting to {}", begin_cell.address);
                                                        
                                                        let tx = self.stream_data_tx.clone();
                                                        let circuit_id = message.circuit_id;
                                                        
                                                        // Spawn connection task
                                                        tokio::spawn(async move {
                                                            match tokio::net::TcpStream::connect(&begin_cell.address).await {
                                                                Ok(stream) => {
                                                                    // Send success (Needs to be communicated back to main loop to send ConnectedCell)
                                                                    // Simplified: We assume success and Main Loop sends Connected.
                                                                    // Wait, we can't easily send Connected from here because we don't have access to Swarm.
                                                                    // We need to send an internal event "Connected".
                                                                    // For now, let's just create the stream and send data events.
                                                                    // BUT we need to store the WriteHalf in `outgoing_streams`.
                                                                    // Does this mean we need to connect inside the main loop? 
                                                                    // Connecting might block? TcpStream::connect is async. 
                                                                    // It's safe to await in select! loop? Yes, but it pauses handling other events.
                                                                    // Better to spawn. But how to get WriteHalf back?
                                                                    // We can use a oneshot channel or similar. 
                                                                    // OR just block slightly (it's async).
                                                                }
                                                                Err(_) => {}
                                                            }
                                                        });
                                                        
                                                        // NOTE: Blocking connect for prototype simplicity
                                                        match tokio::net::TcpStream::connect(&begin_cell.address).await {
                                                            Ok(stream) => {
                                                                let (mut rd, wr) = stream.into_split();
                                                                self.outgoing_streams.insert(message.circuit_id, wr);
                                                                
                                                                // Spawn reader
                                                                let tx = self.stream_data_tx.clone();
                                                                tokio::spawn(async move {
                                                                    let mut buf = [0u8; 4096];
                                                                    loop {
                                                                        match rd.read(&mut buf).await {
                                                                            Ok(0) => break, // EOF
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
                                                                
                                                                // Send CONNECTED cell back
                                                                let connected = ConnectedCell::new("0.0.0.0");
                                                                let relay_resp = vigilnet_crypto::onion::RelayCell::connected(0, &connected);
                                                                if let Ok(encrypted) = vigilnet_crypto::aead::encrypt(circuit.session_key.as_bytes(), &relay_resp.to_bytes()) {
                                                                     let cell = CircuitCell::relay(message.circuit_id, encrypted);
                                                                     let _ = self.swarm.behaviour_mut().circuit.send_request(&peer_id, cell);
                                                                }
                                                            }
                                                            Err(e) => {
                                                                warn!("Failed to connect to {}: {}", begin_cell.address, e);
                                                                // Send END cell?
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
                                 Err(e) => warn!("Failed to decrypt relay cell from {}: {}", peer_id, e),
                             }
                        } else {
                            warn!("Received RELAY cell for unknown circuit {} from {}", message.circuit_id, peer_id);
                        }
                    }
                    _ => {}
                }
            }
            VigilNetEvent::CircuitResponse { request_id: _, message } => {
                match message.cell_type {
                    vigilnet_crypto::onion::CellType::Created => {
                        // Check if this is for OUR circuit building OR if we are relaying
                        if let Some(tx) = self.pending_circuit_requests.remove(&message.circuit_id) {
                            // It's OUR circuit (we are the origin)
                             if let Ok(created) = vigilnet_crypto::onion::CreatedCell::from_bytes(&message.payload) {
                                match self.circuit_builder.handle_created(created) {
                                    Ok(extend_cell) => {
                                        // Send EXTEND to next hop (via Relay cell to first hop)
                                        // Get first hop peer
                                        if let Some(first_hop) = self.circuit_builder.get_first_hop(message.circuit_id) {
                                            if let Ok(peer) = PeerId::from_bytes(&first_hop) {
                                                 let relay_cell = vigilnet_crypto::onion::RelayCell::extend(&extend_cell);
                                                 // TODO: Encrypt relay cell
                                                 // For now sending plaintext relay cell wrapped in CircuitCell
                                                 let cell = CircuitCell::relay(message.circuit_id, relay_cell.to_bytes());
                                                 let _ = self.swarm.behaviour_mut().circuit.send_request(&peer, cell);
                                                 // Re-insert tx to wait for next response?
                                                 // Actually we need to wait for EXTENDED.
                                                 self.pending_circuit_requests.insert(message.circuit_id, tx);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        // If error is just "Ready", then we are done
                                        let _ = tx.send(Ok(message.circuit_id)).await;
                                    }
                                }
                            }
                        } else if let Some((prev_peer, prev_circuit_id)) = self.outbound_circuit_map.get(&(peer_id, message.circuit_id)) {
                            // It's a response we need to RELAY back
                            if let Ok(created) = vigilnet_crypto::onion::CreatedCell::from_bytes(&message.payload) {
                                let extended = vigilnet_crypto::onion::ExtendedCell {
                                    dh_public: created.dh_public
                                };
                                
                                if let Some(circuit) = self.relay_circuits.get(prev_peer, *prev_circuit_id) {
                                    let relay_cell = vigilnet_crypto::onion::RelayCell::extended(&extended);
                                    
                                    // Encrypt logic would go here. For prototype sending raw.
                                    // But wait, the client expects Encrypted payload.
                                    // We encrypt with OUR session key (so client decrypts it and sees ExtendedCell from US?)
                                    // No, client decrypts layer 1 (us), sees RelayCell.
                                    // RelayCell contains payload. Payload is ExtendedCell.
                                    // So we encrypt the RelayCell bytes?
                                    // CircuitCell::relay(id, encrypted_data).
                                    
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
                    vigilnet_crypto::onion::CellType::Extended => {
                        // Handle EXTENDED if we are origin
                         if let Some(tx) = self.pending_circuit_requests.get(&message.circuit_id) {
                             if let Ok(extended) = ExtendedCell::from_bytes(&message.payload) {
                                 // Handle extended
                                 // NOTE: In real impl, payload is inside RelayCell(Extended) which we decrypt first.
                                 // But here we are receiving CircuitCell::Extended? 
                                 // No, `Extended` is a relay command inside a RelayCell.
                                 // CircuitCell::Extended type acts as a direct response in simplified proto?
                                 // Currently `onion.rs` has `CellType::Extended`.
                                 // If we receive `CellType::Extended`, it's a direct response?
                                 // Standard Tor uses RELAY_EXTENDED (command inside RELAY cell).
                                 // But we have `CellType::Extended`.
                                 // Let's assume for prototype it might come as a direct cell or wrapped.
                             }
                         }
                    }
                    _ => {}
                }
            }
            VigilNetEvent::GossipMessage { peer_id, topic, data } => {
                debug!("Gossip from {}: {} bytes", peer_id, data.len());
            }
        }
    }
}

    /// Get the local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
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
                            let peers: Vec<_> = self.connected_peers.iter().cloned().collect();
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
                                    let request_id = self.swarm.behaviour_mut().circuit.send_request(
                                        &PeerId::from_bytes(&entry_peer).unwrap(),
                                        cell
                                    );
                                    info!("Started building circuit {}, request {:?}", circuit_id, request_id);
                                }
                                Err(e) => {
                                    let _ = tx.send(Err(Error::Network(format!("Failed to init circuit: {}", e)))).await;
                                }
                            }
                        }
                        SwarmCommand::Shutdown => {
                            info!("Swarm shutdown requested");
                            break;
                        }
                    }
                }
            }
        }

        info!("Swarm event loop ended");
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<vigilnet_discovery::VigilNetBehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on {}", address);
                let _ = self.notify_tx.send(SwarmNotification::Listening(address)).await;
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to {}", peer_id);
                self.connected_peers.insert(peer_id);
                let _ = self.notify_tx.send(SwarmNotification::PeerConnected(peer_id)).await;
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from {}", peer_id);
                self.connected_peers.remove(&peer_id);
                let _ = self.notify_tx.send(SwarmNotification::PeerDisconnected(peer_id)).await;
            }
            SwarmEvent::Behaviour(behaviour_event) => {
                if let Some(vigilnet_event) = map_behaviour_event(behaviour_event) {
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
                    if !self.connected_peers.contains(&peer_id) {
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
                // In a real implementation, we would add this peer to PathSelector
            }
            VigilNetEvent::IdentifyReceived { peer_id, info } => {
                debug!("Identify from {}: {} protocols", peer_id, info.protocols.len());
                for addr in info.listen_addrs {
                    self.swarm.behaviour_mut().add_address(&peer_id, addr);
                }
            }
            VigilNetEvent::CircuitMessage { peer_id, message, response_channel } => {
                // TODO: Handle acting as a relay (Phase 2 part 2)
                debug!("Received circuit message from {}", peer_id);
            }
            VigilNetEvent::CircuitResponse { request_id: _, message } => {
                match message.cell_type {
                    vigilnet_crypto::onion::CellType::Created => {
                        if let Ok(created) = vigilnet_crypto::onion::CreatedCell::from_bytes(&message.payload) {
                             match self.circuit_builder.handle_created(created) {
                                Ok(extend_cell) => {
                                    // Wrap in Relay cell
                                    let relay_cell = vigilnet_crypto::onion::RelayCell::extend(&extend_cell);
                                    // Wrap in Circuit cell
                                    let circuit_cell = CircuitCell::relay(message.circuit_id, relay_cell.to_bytes()); // NOTE: Encryption missing here!
                                    // In real implementation, we need to encrypt layer by layer
                                    
                                    // For now, let's just send it (this is a simplified implementation stub)
                                    // We need to keep track of which peer is the entry node for this circuit ID to send the response.
                                    // But Response is handled by libp2p request-response based on request_id... 
                                    // Actually CircuitResponse comes from the peer we sent request to.
                                    
                                    // Wait, ExtendedCell needs to go to the SAME peer (the entry node), but inside a Relay cell.
                                    // We don't have the peer ID here easily unless we tracked request_id mapping.
                                    // Simplification: assume we are connected to entry.
                                    warn!("Circuit building step 2 (Extend) not fully implemented in this iteration");
                                }
                                Err(e) => error!("Circuit build error: {}", e),
                            }
                        }
                    }
                    vigilnet_crypto::onion::CellType::Extended => {
                         if let Ok(extended) = ExtendedCell::from_bytes(&message.payload) {
                             match self.circuit_builder.handle_extended(message.circuit_id, extended) {
                                 Ok(Some((extend_cell, maybe_circuit))) => {
                                     if let Some(circuit) = maybe_circuit {
                                         // Circuit complete!
                                         self.active_circuits.insert(message.circuit_id, circuit);
                                         info!("Circuit {} built successfully!", message.circuit_id);
                                         if let Some(tx) = self.pending_circuit_requests.remove(&message.circuit_id) {
                                             let _ = tx.send(Ok(message.circuit_id)).await;
                                         }
                                         let _ = self.notify_tx.send(SwarmNotification::CircuitBuilt(message.circuit_id)).await;
                                     } else {
                                         // Send next EXTEND (via Relay)
                                         // Get first hop
                                         if let Some(first_hop) = self.circuit_builder.get_first_hop(message.circuit_id) {
                                              if let Ok(peer) = PeerId::from_bytes(&first_hop) {
                                                  let relay_cell = vigilnet_crypto::onion::RelayCell::extend(&extend_cell);
                                                  let cell = CircuitCell::relay(message.circuit_id, relay_cell.to_bytes());
                                                  let _ = self.swarm.behaviour_mut().circuit.send_request(&peer, cell);
                                              }
                                         }
                                     }
                                 }
                                 Ok(None) => {}, // Waiting, no action
                                 Err(e) => {
                                     warn!("Failed to handle EXTENDED for {}: {}", message.circuit_id, e);
                                     if let Some(tx) = self.pending_circuit_requests.remove(&message.circuit_id) {
                                          let _ = tx.send(Err(Error::Network(format!("Circuit failed: {}", e)))).await;
                                     }
                                 }
                             }
                         }
                    }
                    _ => {}
                }
            }
            VigilNetEvent::GossipMessage { peer_id, topic, data } => {
                debug!("Gossip from {}: {} bytes", peer_id, data.len());
            }
        }
    }
}
