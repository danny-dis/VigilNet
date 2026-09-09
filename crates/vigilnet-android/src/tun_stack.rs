use async_trait::async_trait;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use smoltcp::iface::{Config, Interface, SocketSet, SocketHandle};

/// Trait for network backends that can act as a proxy for egress traffic
#[async_trait::async_trait]
pub trait BackendProxy: Send + Sync {
    /// Connect to a destination through this backend
    async fn connect(&self, host: &str, port: u16) -> crate::Result<Box<dyn BackendStream>>;
    
    /// Resolve a hostname through this backend
    async fn resolve(&self, host: &str) -> crate::Result<Vec<std::net::IpAddr>>;
}

/// Unified stream type for different network backends
pub trait BackendStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> BackendStream for T {}

#[async_trait::async_trait]
impl BackendProxy for vigilnet_tor::TorClient {
    async fn connect(&self, host: &str, port: u16) -> crate::Result<Box<dyn BackendStream>> {
        let stream = self.connect(host, port).await?;
        Ok(Box::new(stream))
    }

    async fn resolve(&self, host: &str) -> crate::Result<Vec<std::net::IpAddr>> {
        self.resolve(host).await
    }
}

/// Userspace TCP/IP stack using smoltcp
pub struct TunStack {
    device: VirtualTunDevice,
    iface: Interface,
    socket_set: SocketSet<'static>,
    egress: Arc<dyn BackendProxy>,
    /// Map of socket handle -> proxy session
    /// Used to track proxy connections for established sockets
    connections: HashMap<SocketHandle, ProxySession>,
}

impl TunStack {
    pub fn new(mut tx: mpsc::Sender<TunPacket>, egress: Arc<dyn BackendProxy>) -> Self {
        // Create virtual device with a channel to send packets back to Android
        // We don't need an RX channel in the device because we feed packets manually via `receive_packet`
        let mut device = VirtualTunDevice {
            tx: tx,
            mtu: 1500,
            rx_buffer: std::collections::VecDeque::new(),
        };

        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 42; 
        
        let mut iface = Interface::new(config, &mut device, Instant::now());
        
        // Configure interface IP (gateway for the phone)
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 24)).ok();
        });
        
        // Add default route
        iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1)).ok();

        Self {
            device,
            iface,
            socket_set: SocketSet::new(vec![]),
            egress,
            connections: HashMap::new(),
        }
    }

    /// Main poll loop
    pub async fn poll(&mut self, packet: Option<TunPacket>) {
        // 1. Inject packet if present
        if let Some(pkt) = packet {
            if !self.inspect_and_create_socket(&pkt.data) {
                self.device.rx_buffer.push_back(pkt.data);
            }
        }

        // 2. Poll the interface
        let timestamp = Instant::now();
        if let Err(e) = self.iface.poll(timestamp, &mut self.device, &mut self.socket_set) {
            debug!("Poll error: {}", e);
        }

        // 3. Process sockets (Data Pump)
        let mut remove_handles = Vec::new();

        for (handle, socket) in self.socket_set.iter_mut() {
            match socket {
                smoltcp::socket::tcp::Socket::Open(ref mut s) => {
                    let remote = s.remote_endpoint();
                    
                    // A. Check connectivity state
                    if s.state() == smoltcp::socket::tcp::State::Established {
                        // Ensure we have a proxy session
                        if !self.connections.contains_key(&handle) {
                             if let Some(endpoint) = remote {
                                 if let IpAddress::Ipv4(addr) = endpoint.addr {
                                     let dst_ip = Ipv4Addr::from(addr);
                                     let dst_port = endpoint.port;
                                     
                                     info!("Socket established: -> {}:{}", dst_ip, dst_port);
                                     
                                     // Create channels
                                     let (app_tx, mut app_rx) = mpsc::channel::<bytes::Bytes>(1024);
                                     let (tor_tx, mut tor_rx) = mpsc::channel::<bytes::Bytes>(1024);
                                     
                                     self.connections.insert(handle, ProxySession {
                                         tx: app_tx,
                                         rx: tor_rx,
                                     });
                                     
                                     // Spawn proxy task
                                     let egress = self.egress.clone();
                                     tokio::spawn(async move {
                                         info!("Proxy task starting for {}:{}", dst_ip, dst_port);
                                         
                                         // Connect through egress (default is Tor, but could be a chain)
                                         let connect_res = egress.connect(&dst_ip.to_string(), dst_port).await;
                                         
                                         match connect_res {
                                             Ok(mut stream) => {
                                                 info!("Egress stream connected to {}:{}", dst_ip, dst_port);
                                                 
                                                 // Pump loop
                                                 use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                                 let mut buf = [0u8; 4096];
                                                 
                                                 loop {
                                                     tokio::select! {
                                                         // App -> Tor
                                                         msg = app_rx.recv() => {
                                                             match msg {
                                                                 Some(data) => {
                                                                     if let Err(e) = stream.write_all(&data).await {
                                                                         error!("Write to Tor failed: {}", e);
                                                                         break;
                                                                     }
                                                                 }
                                                                 None => break, // Channel closed
                                                             }
                                                         }
                                                         // Tor -> App
                                                         res = stream.read(&mut buf) => {
                                                             match res {
                                                                 Ok(n) if n > 0 => {
                                                                     if let Err(_) = tor_tx.send(buf[..n].to_vec()).await {
                                                                         break;
                                                                     }
                                                                 }
                                                                 _ => break, // EOF or error
                                                             }
                                                         }
                                                     }
                                                 }
                                             }
                                             Err(e) => {
                                                 error!("Tor connect failed: {}", e);
                                             }
                                         }
                                         info!("Proxy task finished for {}:{}", dst_ip, dst_port);
                                     });
                                 }
                             }
                        }
                        
                        // B. Pump Data
                        if let Some(session) = self.connections.get_mut(&handle) {
                            // 1. Rx from App (smoltcp socket) -> Tx to Proxy Task
                            if s.can_recv() {
                                let mut data = vec![0u8; 4096];
                                match s.recv_slice(&mut data) {
                                    Ok(n) if n > 0 => {
                                        data.truncate(n);
                                        let _ = session.tx.try_send(bytes::Bytes::from(data)); 
                                    }
                                    _ => {}
                                }
                            }
                            
                            // 2. Rx from Proxy Task -> Tx to App (smoltcp socket)
                            if s.can_send() {
                                match session.rx.try_recv() {
                                    Ok(data) => {
                                        s.send_slice(&data).ok();
                                    }
                                    Err(_) => {}
                                }
                            }
                        }

                    } else if s.state() == smoltcp::socket::tcp::State::Closed {
                        remove_handles.push(handle);
                        self.connections.remove(&handle);
                    }
                }
                _ => {}
            }
        }
        
        for handle in remove_handles {
            self.socket_set.remove(handle);
        }
    }

    /// Inspect incoming packet and create ephemeral socket if needed
    /// Returns true if the packet was consumed/handled and should NOT be passed to smoltcp
    fn inspect_and_create_socket(&mut self, data: &[u8]) -> bool {
        match etherparse::Ipv4Header::from_slice(data) {
            Ok((header, payload)) => {
                // Check if this is a DNS query (UDP port 53)
                if header.protocol == 17 { // UDP
                    if let Ok((udp_header, udp_payload)) = etherparse::UdpHeader::from_slice(payload) {
                        if udp_header.destination_port == 53 {
                            debug!("Intercepted DNS query via UDP/53");
                            self.handle_dns_query(header, udp_header, udp_payload);
                            return true; // Consumed (DNS)
                        } else {
                            // Drop all other IP traffic (Tor doesn't support generic UDP)
                            // This prevents smoltcp from sending ICMP Port Unreachable
                            return true; // Consumed (Dropped)
                        }
                    }
                    // Malformed UDP? Drop it.
                    return true;
                }

                if header.protocol == 6 { // TCP
                    // Parse TCP to check for SYN
                    if let Ok((tcp_header, _)) = etherparse::TcpHeader::from_slice(payload) {
                        if tcp_header.syn && !tcp_header.ack {
                            let dst_ip = IpAddress::Ipv4(Ipv4Address(header.destination));
                            let dst_port = tcp_header.destination_port;

                            // Create socket if not exists for this 4-tuple?
                            // smoltcp's listen() binds to local endpoint.
                            // We act as the server, so we bind to the *destination* address.
                            
                            // Simple check: do we have a listener?
                            // For MVP, we just create a new socket for every SYN.
                            // Real impl needs to check if we already have a socket for this flow.
                            
                            debug!("JIT Socket: intercepting conn to {}:{}", dst_ip, dst_port);
                            
                            let rx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]);
                            let tx_buffer = smoltcp::socket::tcp::SocketBuffer::new(vec![0; 65535]);
                            let mut socket = smoltcp::socket::tcp::Socket::new(rx_buffer, tx_buffer);
                            
                            if let Err(e) = socket.listen((dst_ip, dst_port)) {
                                error!("Failed to bind JIT socket: {}", e);
                            } else {
                                self.socket_set.add(socket);
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
        false // Pass to smoltcp (TCP, ICMP, etc.)
    }

    /// Handle intercepted DNS query
    fn handle_dns_query(&self, ip_header: etherparse::Ipv4Header, udp_header: etherparse::UdpHeader, payload: &[u8]) {
        use simple_dns::{Packet, PacketFlag, ResourceRecord, Name, CLASS, TYPE, RData};
        
        // Parse DNS packet
        let packet = match Packet::parse(payload) {
            Ok(p) => p,
            Err(e) => {
                debug!("Failed to parse DNS packet: {}", e);
                return;
            }
        };

        if packet.questions.is_empty() {
            return;
        }

        let question = packet.questions[0].clone();
        let domain = question.qname.to_string();
        let tx = self.device.tx.clone(); // Access tx directly from device field
        
        let src_ip = ip_header.source;
        let dst_ip = ip_header.destination; 
        let src_port = udp_header.source_port;
        let dst_port = udp_header.destination_port;
        let msg_id = packet.id;

        info!("Resolving DNS query for: {}", domain);

        let egress = self.egress.clone();
        tokio::spawn(async move {
            // Resolve via backend (e.g. Tor or a bridge)
            let resolved_ip = match egress.resolve(&domain).await {
                Ok(ips) => ips.into_iter().next(),
                Err(e) => {
                    error!("DNS resolution failed for {}: {}", domain, e);
                    None
                }
            };
            
            // Construct response
            let mut reply = Packet::new_reply(msg_id);
            reply.questions.push(question);
            
            if let Some(std::net::IpAddr::V4(ip)) = resolved_ip {
                info!("Resolved {} -> {}", domain, ip);
                let rdata = RData::A(u32::from_be_bytes(ip.octets()));
                match Name::new(&domain) {
                    Ok(name) => {
                        let record = ResourceRecord::new(name, CLASS::IN, 300, rdata);
                        reply.answers.push(record);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to create DNS name for '{}': {}", domain, e);
                        reply.header.response_code = simple_dns::rdata::RCODE::ServerFailure;
                    }
                }
            } else {
                // If failed, we might want to return ServerFailure or just timeout
                reply.header.response_code = simple_dns::rdata::RCODE::ServerFailure;
            }

            // Serialize DNS packet
            let dns_bytes = match reply.build_bytes_vec() {
                Ok(b) => b,
                Err(e) => {
                    error!("Failed to build DNS reply: {}", e);
                    return;
                }
            };
            
            // Wrap in UDP/IP headers (swapping src/dst)
            let builder = etherparse::PacketBuilder::
                ipv4(dst_ip, src_ip, 20) // 20 TTL
                .udp(dst_port, src_port);

            let mut final_packet = Vec::<u8>::with_capacity(builder.size(dns_bytes.len()));
            if let Err(e) = builder.write(&mut final_packet, &dns_bytes) {
                error!("Failed to build UDP packet: {}", e);
                return;
            }

            // Inject back to TUN
            let data = bytes::Bytes::from(final_packet);
            if let Err(e) = tx.send(TunPacket { data }).await {
                 error!("Failed to send DNS reply to TUN: {}", e);
            }
        });
    }
}

struct ProxySession {
    tx: mpsc::Sender<bytes::Bytes>,
    rx: mpsc::Receiver<bytes::Bytes>,
}

// Re-implementing VirtualTunDevice correctly
pub struct VirtualTunDevice {
    pub tx: mpsc::Sender<TunPacket>,
    pub mtu: usize,
    pub rx_buffer: std::collections::VecDeque<bytes::Bytes>,
}

impl Device for VirtualTunDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(data) = self.rx_buffer.pop_front() {
            Some((RxToken { buffer: data }, TxToken { tx: self.tx.clone() }))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken { tx: self.tx.clone() })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct RxToken {
    buffer: bytes::Bytes,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = self.buffer.to_vec(); // still a copy unfortunately for RxToken consume
        f(&mut buf)
    }
}

pub struct TxToken {
    tx: mpsc::Sender<TunPacket>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        
        // Send packet back to TUN asynchronously
        // Since consume is not async, we spawn a task or use try_send
        let tx = self.tx;
        tokio::spawn(async move {
            let data = bytes::Bytes::from(buffer);
            if let Err(e) = tx.send(TunPacket { data }).await {
                error!("Failed to send packet to TUN from stack: {}", e);
            }
        });
        
        result
    }
}

