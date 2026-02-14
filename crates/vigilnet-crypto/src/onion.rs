//! Onion encryption and packet handling
//!
//! Implements multi-layer encryption for anonymous routing.

use crate::{aead, CryptoError, Result, SessionKey};

/// A single layer of onion encryption
#[derive(Debug, Clone)]
pub struct OnionLayer {
    /// Session key for this layer
    pub key: SessionKey,
    /// Hop identifier (public key of relay)
    pub hop_id: [u8; 32],
}

/// An onion-encrypted packet
#[derive(Debug, Clone)]
pub struct OnionPacket {
    /// Circuit identifier
    pub circuit_id: u32,
    /// Encrypted payload (multiple layers)
    pub payload: Vec<u8>,
}

impl OnionPacket {
    /// Create a new onion packet by wrapping payload in multiple encryption layers
    ///
    /// Layers are applied in reverse order (exit first, then middle, then entry)
    /// so that unwrapping happens entry → middle → exit
    pub fn wrap(payload: &[u8], layers: &[OnionLayer], circuit_id: u32) -> Result<Self> {
        let mut data = payload.to_vec();

        // Encrypt from exit to entry (reverse order)
        for layer in layers.iter().rev() {
            data = aead::encrypt(layer.key.as_bytes(), &data)?;
        }

        Ok(Self {
            circuit_id,
            payload: data,
        })
    }

    /// Unwrap one layer of encryption
    ///
    /// Returns the decrypted payload for forwarding to the next hop
    pub fn unwrap_layer(&self, key: &SessionKey) -> Result<Vec<u8>> {
        aead::decrypt(key.as_bytes(), &self.payload)
    }

    /// Serialize packet to bytes for network transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + self.payload.len());
        bytes.extend_from_slice(&self.circuit_id.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize packet from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(CryptoError::DecryptionFailed("Packet too short".to_string()));
        }

        let circuit_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let payload = data[4..].to_vec();

        Ok(Self { circuit_id, payload })
    }
}

/// Cell types for circuit management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellType {
    /// Create a new circuit
    Create = 0,
    /// Created response
    Created = 1,
    /// Extend circuit to another hop
    Extend = 2,
    /// Extended response
    Extended = 3,
    /// Relay data through circuit
    Relay = 4,
    /// Destroy circuit
    Destroy = 5,
}

impl TryFrom<u8> for CellType {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Create),
            1 => Ok(Self::Created),
            2 => Ok(Self::Extend),
            3 => Ok(Self::Extended),
            4 => Ok(Self::Relay),
            5 => Ok(Self::Destroy),
            _ => Err(CryptoError::DecryptionFailed(format!(
                "Unknown cell type: {}",
                value
            ))),
        }
    }
}

/// CREATE cell - sent to establish a new circuit hop
#[derive(Debug, Clone)]
pub struct CreateCell {
    /// Circuit ID for this hop
    pub circuit_id: u32,
    /// Our ephemeral X25519 public key
    pub dh_public: [u8; 32],
}

impl CreateCell {
    /// Create a new CREATE cell
    pub fn new(circuit_id: u32, dh_public: [u8; 32]) -> Self {
        Self { circuit_id, dh_public }
    }

    /// Serialize to bytes: circuit_id (4) + dh_public (32)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&self.circuit_id.to_be_bytes());
        bytes.extend_from_slice(&self.dh_public);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 36 {
            return Err(CryptoError::DecryptionFailed("CreateCell too short".into()));
        }
        let circuit_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[4..36]);
        Ok(Self { circuit_id, dh_public })
    }
}

/// CREATED cell - response to CREATE with relay's DH public key
#[derive(Debug, Clone)]
pub struct CreatedCell {
    /// Circuit ID (echoed back)
    pub circuit_id: u32,
    /// Relay's ephemeral X25519 public key
    pub dh_public: [u8; 32],
}

impl CreatedCell {
    /// Create a new CREATED cell
    pub fn new(circuit_id: u32, dh_public: [u8; 32]) -> Self {
        Self { circuit_id, dh_public }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(36);
        bytes.extend_from_slice(&self.circuit_id.to_be_bytes());
        bytes.extend_from_slice(&self.dh_public);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 36 {
            return Err(CryptoError::DecryptionFailed("CreatedCell too short".into()));
        }
        let circuit_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[4..36]);
        Ok(Self { circuit_id, dh_public })
    }
}

/// EXTEND cell - sent through circuit to extend to next hop
#[derive(Debug, Clone)]
pub struct ExtendCell {
    /// Peer ID of the next hop (32 bytes, truncated from libp2p PeerId)
    pub next_hop: [u8; 32],
    /// Our ephemeral DH public key for the next hop
    pub dh_public: [u8; 32],
}

impl ExtendCell {
    /// Create a new EXTEND cell
    pub fn new(next_hop: [u8; 32], dh_public: [u8; 32]) -> Self {
        Self { next_hop, dh_public }
    }

    /// Serialize to bytes: next_hop (32) + dh_public (32)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.next_hop);
        bytes.extend_from_slice(&self.dh_public);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 64 {
            return Err(CryptoError::DecryptionFailed("ExtendCell too short".into()));
        }
        let mut next_hop = [0u8; 32];
        next_hop.copy_from_slice(&data[0..32]);
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[32..64]);
        Ok(Self { next_hop, dh_public })
    }
}

/// EXTENDED cell - response to EXTEND with next hop's DH public key
#[derive(Debug, Clone)]
pub struct ExtendedCell {
    /// Next hop's ephemeral X25519 public key
    pub dh_public: [u8; 32],
}

impl ExtendedCell {
    /// Create a new EXTENDED cell
    pub fn new(dh_public: [u8; 32]) -> Self {
        Self { dh_public }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.dh_public.to_vec()
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            return Err(CryptoError::DecryptionFailed("ExtendedCell too short".into()));
        }
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&data[0..32]);
        Ok(Self { dh_public })
    }
}

/// BEGIN cell - open a stream to a target address
#[derive(Debug, Clone)]
pub struct BeginCell {
    /// Target address string (IP:Port or Domain:Port)
    pub address: String,
}

impl BeginCell {
    /// Create a new BEGIN cell
    pub fn new(address: impl Into<String>) -> Self {
        Self { address: address.into() }
    }

    /// Serialize to bytes: address_len (2) + address_bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let addr_bytes = self.address.as_bytes();
        let len = addr_bytes.len() as u16;
        let mut bytes = Vec::with_capacity(2 + addr_bytes.len());
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(addr_bytes);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(CryptoError::DecryptionFailed("BeginCell too short".into()));
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            return Err(CryptoError::DecryptionFailed("BeginCell truncated".into()));
        }
        
        let address = String::from_utf8(data[2..2 + len].to_vec())
            .map_err(|_| CryptoError::DecryptionFailed("Invalid UTF-8 address".into()))?;
            
        Ok(Self { address })
    }
}

/// CONNECTED cell - confirmation that stream is open
#[derive(Debug, Clone)]
pub struct ConnectedCell {
    /// Bind address (for BIND request, usually 0.0.0.0 for CONNECT)
    pub bind_addr: String,
}

impl ConnectedCell {
    /// Create a new CONNECTED cell
    pub fn new(bind_addr: impl Into<String>) -> Self {
        Self { bind_addr: bind_addr.into() }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let addr_bytes = self.bind_addr.as_bytes();
        let len = addr_bytes.len() as u16;
        let mut bytes = Vec::with_capacity(2 + addr_bytes.len());
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(addr_bytes);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
         // Similar structure to BeginCell for now
        if data.len() < 2 {
            // It's allowed to be empty or just contain 0 len
            if data.is_empty() {
                return Ok(Self { bind_addr: String::new() });
            }
        }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + len {
            return Ok(Self { bind_addr: String::new() }); // Tolerate truncation for now
        }
        
        let bind_addr = String::from_utf8(data[2..2 + len].to_vec())
            .unwrap_or_default();
            
        Ok(Self { bind_addr })
    }
}

/// END cell - stream ended
#[derive(Debug, Clone)]
pub struct EndCell {
    /// Reason code (0 = normal, 1 = forbidden, 2 = failed)
    pub reason: u8,
}

impl EndCell {
    pub fn new(reason: u8) -> Self {
        Self { reason }
    }
    
    pub fn to_bytes(&self) -> Vec<u8> {
        vec![self.reason]
    }
    
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self { reason: 0 });
        }
        Ok(Self { reason: data[0] })
    }
}

/// Relay command types for RELAY cells
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCommand {
    /// Begin a new stream
    Begin = 0,
    /// Data payload
    Data = 1,
    /// End a stream (e.g. TCP disconnect)
    End = 3,
    /// Connected notification
    Connected = 4,
    /// Extend the circuit to a new hop
    Extend = 5,
    /// Circuit extended successfully
    Extended = 6,
    /// Truncate the circuit (tear down from a hop)
    Truncate = 7,
    /// Circuit truncated
    Truncated = 8,
    /// Drop/Padding cell (ignored by receiver)
    Drop = 9,
}

impl TryFrom<u8> for RelayCommand {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Begin),
            1 => Ok(Self::Data),
            3 => Ok(Self::End),
            4 => Ok(Self::Connected),
            5 => Ok(Self::Extend),
            6 => Ok(Self::Extended),
            7 => Ok(Self::Truncate),
            8 => Ok(Self::Truncated),
            9 => Ok(Self::Drop),
            _ => Err(CryptoError::DecryptionFailed(format!(
                "Unknown relay command: {}",
                value
            ))),
        }
    }
}

impl From<RelayCommand> for u8 {
    fn from(cmd: RelayCommand) -> u8 {
        cmd as u8
    }
}

/// RELAY cell - carries data or commands through the circuit
#[derive(Debug, Clone)]
pub struct RelayCell {
    /// Stream ID within the circuit
    pub stream_id: u16,
    /// Relay command
    pub command: RelayCommand,
    /// Payload data
    pub data: Vec<u8>,
}

impl RelayCell {
    /// Create a new RELAY cell with data
    pub fn data(stream_id: u16, data: Vec<u8>) -> Self {
        Self {
            stream_id,
            command: RelayCommand::Data,
            data,
        }
    }

    /// Create an EXTEND relay cell
    pub fn extend(extend_cell: &ExtendCell) -> Self {
        Self {
            stream_id: 0,
            command: RelayCommand::Extend,
            data: extend_cell.to_bytes(),
        }
    }

    /// Create an EXTENDED relay cell
    pub fn extended(extended_cell: &ExtendedCell) -> Self {
        Self {
            stream_id: 0,
            command: RelayCommand::Extended,
            data: extended_cell.to_bytes(),
        }
    }

    /// Create a BEGIN relay cell
    pub fn begin(stream_id: u16, begin_cell: &BeginCell) -> Self {
        Self {
            stream_id,
            command: RelayCommand::Begin,
            data: begin_cell.to_bytes(),
        }
    }

    /// Create a CONNECTED relay cell
    pub fn connected(stream_id: u16, connected_cell: &ConnectedCell) -> Self {
         Self {
            stream_id,
            command: RelayCommand::Connected,
            data: connected_cell.to_bytes(),
        }
    }

    /// Create an END relay cell
    pub fn end(stream_id: u16, end_cell: &EndCell) -> Self {
         Self {
            stream_id,
            command: RelayCommand::End,
            data: end_cell.to_bytes(),
        }
    }

    /// Serialize to bytes: stream_id (2) + command (1) + length (2) + data
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.data.len() as u16;
        let mut bytes = Vec::with_capacity(5 + self.data.len());
        bytes.extend_from_slice(&self.stream_id.to_be_bytes());
        bytes.push(self.command as u8);
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(CryptoError::DecryptionFailed("RelayCell too short".into()));
        }
        let stream_id = u16::from_be_bytes([data[0], data[1]]);
        let command = RelayCommand::try_from(data[2])?;
        let len = u16::from_be_bytes([data[3], data[4]]) as usize;
        
        if data.len() < 5 + len {
            return Err(CryptoError::DecryptionFailed("RelayCell data truncated".into()));
        }
        
        let payload = data[5..5 + len].to_vec();
        Ok(Self {
            stream_id,
            command,
            data: payload,
        })
    }
}

/// Circuit cell wrapper - the top-level message format
#[derive(Debug, Clone)]
pub struct CircuitCell {
    /// Circuit ID
    pub circuit_id: u32,
    /// Cell type
    pub cell_type: CellType,
    /// Cell payload
    pub payload: Vec<u8>,
}

impl CircuitCell {
    /// Create a CREATE cell
    pub fn create(cell: &CreateCell) -> Self {
        Self {
            circuit_id: cell.circuit_id,
            cell_type: CellType::Create,
            payload: cell.dh_public.to_vec(),
        }
    }

    /// Create a CREATED cell
    pub fn created(cell: &CreatedCell) -> Self {
        Self {
            circuit_id: cell.circuit_id,
            cell_type: CellType::Created,
            payload: cell.dh_public.to_vec(),
        }
    }

    /// Create a RELAY cell (encrypted payload)
    pub fn relay(circuit_id: u32, encrypted_payload: Vec<u8>) -> Self {
        Self {
            circuit_id,
            cell_type: CellType::Relay,
            payload: encrypted_payload,
        }
    }

    /// Create a DESTROY cell
    pub fn destroy(circuit_id: u32) -> Self {
        Self {
            circuit_id,
            cell_type: CellType::Destroy,
            payload: Vec::new(),
        }
    }

    /// Serialize to bytes: circuit_id (4) + cell_type (1) + payload_len (2) + payload
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut bytes = Vec::with_capacity(7 + self.payload.len());
        bytes.extend_from_slice(&self.circuit_id.to_be_bytes());
        bytes.push(self.cell_type as u8);
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 7 {
            return Err(CryptoError::DecryptionFailed("CircuitCell too short".into()));
        }
        let circuit_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let cell_type = CellType::try_from(data[4])?;
        let len = u16::from_be_bytes([data[5], data[6]]) as usize;
        
        if data.len() < 7 + len {
            return Err(CryptoError::DecryptionFailed("CircuitCell payload truncated".into()));
        }
        
        let payload = data[7..7 + len].to_vec();
        Ok(Self {
            circuit_id,
            cell_type,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onion_wrap_unwrap() {
        // Create 3 layers (3-hop circuit)
        let layers: Vec<OnionLayer> = (0..3)
            .map(|i| OnionLayer {
                key: SessionKey::from_shared_secret([i as u8; 32]),
                hop_id: [i as u8; 32],
            })
            .collect();

        let original = b"Hello from the origin!";
        let packet = OnionPacket::wrap(original, &layers, 12345).unwrap();

        // Unwrap each layer in order
        let mut data = packet.payload.clone();
        for layer in &layers {
            data = aead::decrypt(layer.key.as_bytes(), &data).unwrap();
        }

        assert_eq!(data.as_slice(), original.as_slice());
    }

    #[test]
    fn test_packet_serialization() {
        let packet = OnionPacket {
            circuit_id: 42,
            payload: vec![1, 2, 3, 4, 5],
        };

        let bytes = packet.to_bytes();
        let restored = OnionPacket::from_bytes(&bytes).unwrap();

        assert_eq!(packet.circuit_id, restored.circuit_id);
        assert_eq!(packet.payload, restored.payload);
    }

    #[test]
    fn test_create_cell_serialization() {
        let cell = CreateCell::new(42, [0x42u8; 32]);
        let bytes = cell.to_bytes();
        let restored = CreateCell::from_bytes(&bytes).unwrap();
        
        assert_eq!(cell.circuit_id, restored.circuit_id);
        assert_eq!(cell.dh_public, restored.dh_public);
    }

    #[test]
    fn test_created_cell_serialization() {
        let cell = CreatedCell::new(42, [0x42u8; 32]);
        let bytes = cell.to_bytes();
        let restored = CreatedCell::from_bytes(&bytes).unwrap();
        
        assert_eq!(cell.circuit_id, restored.circuit_id);
    }

    #[test]
    fn test_extend_cell_serialization() {
        let cell = ExtendCell::new([0x41u8; 32], [0x42u8; 32]);
        let bytes = cell.to_bytes();
        let restored = ExtendCell::from_bytes(&bytes).unwrap();
        
        assert_eq!(cell.next_hop, restored.next_hop);
        assert_eq!(cell.dh_public, restored.dh_public);
    }

    #[test]
    fn test_begin_cell_serialization() {
        let cell = BeginCell::new("192.168.1.1:8080");
        let bytes = cell.to_bytes();
        let restored = BeginCell::from_bytes(&bytes).unwrap();
        
        assert_eq!(cell.address, restored.address);
    }

    #[test]
    fn test_relay_cell_serialization() {
        let cell = RelayCell::data(1, vec![1, 2, 3, 4]);
        let bytes = cell.to_bytes();
        let restored = RelayCell::from_bytes(&bytes).unwrap();
        
        assert_eq!(cell.stream_id, restored.stream_id);
        assert_eq!(cell.command, restored.command);
        assert_eq!(cell.data, restored.data);
    }

    #[test]
    fn test_circuit_cell_serialization() {
        let create_cell = CreateCell::new(42, [0x42u8; 32]);
        let cell = CircuitCell::create(&create_cell);
        let bytes = cell.to_bytes();
        let restored = CircuitCell::from_bytes(&bytes).unwrap();
        
        assert_eq!(cell.circuit_id, restored.circuit_id);
        assert_eq!(cell.cell_type, CellType::Create);
    }

    #[test]
    fn test_cell_type_conversion() {
        assert_eq!(CellType::try_from(0).unwrap(), CellType::Create);
        assert_eq!(CellType::try_from(1).unwrap(), CellType::Created);
        assert_eq!(CellType::try_from(4).unwrap(), CellType::Relay);
        assert_eq!(CellType::try_from(5).unwrap(), CellType::Destroy);
    }

    #[test]
    fn test_relay_command_conversion() {
        assert_eq!(RelayCommand::try_from(0).unwrap(), RelayCommand::Begin);
        assert_eq!(RelayCommand::try_from(1).unwrap(), RelayCommand::Data);
        assert_eq!(RelayCommand::try_from(3).unwrap(), RelayCommand::End);
    }

    #[test]
    fn test_packet_truncated() {
        let result = OnionPacket::from_bytes(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_cell_truncated() {
        let result = CreateCell::from_bytes(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_single_layer_onion() {
        let layers = vec![OnionLayer {
            key: SessionKey::from_shared_secret([0x42u8; 32]),
            hop_id: [0x43u8; 32],
        }];
        
        let original = b"Test";
        let packet = OnionPacket::wrap(original, &layers, 1).unwrap();
        
        let unwrapped = packet.unwrap_layer(&layers[0].key).unwrap();
        assert_eq!(unwrapped.as_slice(), original);
    }
}
