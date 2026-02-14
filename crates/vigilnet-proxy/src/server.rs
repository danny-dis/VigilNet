use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use vigilnet_core::Node;
use vigilnet_crypto::{
    session::{Session, SessionMessage},
    x3dh::{IdentityKeyPair, OneTimePreKey, PreKeyBundle, SignedPreKey},
    CryptoError,
};

const MSG_TYPE_PREKEY_REQUEST: u8 = 0x10;
const MSG_TYPE_PREKEY_RESPONSE: u8 = 0x11;
const MSG_TYPE_ENCRYPTED_DATA: u8 = 0x20;
const MSG_TYPE_SESSION_ERROR: u8 = 0xFF;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("SOCKS5 error: {0}")]
    Socks5(String),
    #[error("E2EE not enabled")]
    E2EENotEnabled,
    #[error("Session not established")]
    NoSession,
    #[error("Invalid E2EE message: {0}")]
    InvalidE2EEMessage(String),
}

impl From<CryptoError> for ProxyError {
    fn from(e: CryptoError) -> Self {
        ProxyError::Crypto(e)
    }
}

pub struct E2EESession {
    session: Session,
    peer_identity: [u8; 32],
}

pub struct PreKeyStore {
    identity_key: IdentityKeyPair,
    signed_prekey: SignedPreKey,
    one_time_prekeys: Vec<OneTimePreKey>,
}

impl PreKeyStore {
    pub fn new() -> Self {
        let identity_key = IdentityKeyPair::generate();
        let signed_prekey = SignedPreKey::generate(&identity_key, 1);
        
        let one_time_prekeys = (0..10)
            .map(|i| OneTimePreKey::generate(i))
            .collect();

        Self {
            identity_key,
            signed_prekey,
            one_time_prekeys,
        }
    }

    pub fn get_prekey_bundle(&self) -> PreKeyBundle {
        let otpk = self.one_time_prekeys.first().cloned();
        PreKeyBundle {
            identity_key: self.identity_key.identity_public,
            signed_prekey: self.signed_prekey.clone(),
            one_time_prekey: otpk,
        }
    }

    pub fn consume_one_time_prekey(&mut self, id: u32) -> Option<OneTimePreKey> {
        self.one_time_prekeys.retain(|k| k.id != id);
        self.one_time_prekeys.iter()
            .find(|k| k.id == id)
            .cloned()
    }

    pub fn identity_key(&self) -> &IdentityKeyPair {
        &self.identity_key
    }

    pub fn signed_prekey(&self) -> &SignedPreKey {
        &self.signed_prekey
    }

    pub fn generate_new_signed_prekey(&mut self) {
        let new_id = self.signed_prekey.id + 1;
        self.signed_prekey = SignedPreKey::generate(&self.identity_key, new_id);
    }
}

pub struct SocksProxy {
    listen_addr: SocketAddr,
    node: Arc<Node>,
    enable_e2ee: bool,
    prekey_store: Arc<RwLock<PreKeyStore>>,
    sessions: Arc<RwLock<HashMap<String, E2EESession>>>,
}

impl SocksProxy {
    pub fn new(listen_addr: SocketAddr, node: Arc<Node>) -> Self {
        Self {
            listen_addr,
            node,
            enable_e2ee: false,
            prekey_store: Arc::new(RwLock::new(PreKeyStore::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn enable_e2ee(mut self) -> Self {
        self.enable_e2ee = true;
        self
    }

    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        
        if self.enable_e2ee {
            info!("SOCKS5 proxy with E2EE listening on {}", self.listen_addr);
        } else {
            info!("SOCKS5 proxy listening on {}", self.listen_addr);
        }

        loop {
            let (stream, addr) = listener.accept().await?;
            debug!("Incoming SOCKS5 connection from {}", addr);
            
            let node = self.node.clone();
            let enable_e2ee = self.enable_e2ee;
            let prekey_store = Arc::clone(&self.prekey_store);
            let sessions = Arc::clone(&self.sessions);
            
            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, node, enable_e2ee, prekey_store, sessions).await {
                    warn!("SOCKS5 client error from {}: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    node: Arc<Node>,
    enable_e2ee: bool,
    prekey_store: Arc<RwLock<PreKeyStore>>,
    sessions: Arc<RwLock<HashMap<String, E2EESession>>>,
) -> Result<(), ProxyError> {
    let mut version = [0u8; 1];
    stream.read_exact(&mut version).await?;
    if version[0] != 0x05 {
        return Err(ProxyError::Socks5("Not SOCKS5".to_string()));
    }

    let mut nmethods = [0u8; 1];
    stream.read_exact(&mut nmethods).await?;
    let mut methods = vec![0u8; nmethods[0] as usize];
    stream.read_exact(&mut methods).await?;

    if enable_e2ee {
        stream.write_all(&[0x05, 0x05]).await?;
    } else {
        stream.write_all(&[0x05, 0x00]).await?;
    }

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    
    let ver = header[0];
    let cmd = header[1];
    let atyp = header[3];

    if ver != 0x05 {
        return Err(ProxyError::Socks5("Not SOCKS5 request".to_string()));
    }

    if cmd != 0x01 {
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
        return Err(ProxyError::Socks5("Only CONNECT supported".to_string()));
    }

    let target_addr = match atyp {
        0x01 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            format!("{}.{}.{}.{}", buf[0], buf[1], buf[2], buf[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut buf).await?;
            String::from_utf8_lossy(&buf).to_string()
        }
        _ => {
            stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
            return Err(ProxyError::Socks5("Unsupported address type".to_string()));
        }
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);
    
    let target = format!("{}:{}", target_addr, port);
    info!("SOCKS5 CONNECT request to {}", target);

    if enable_e2ee {
        handle_e2ee_connection(stream, node, target, prekey_store, sessions).await
    } else {
        handle_plain_connection(stream, node, target).await
    }
}

async fn handle_e2ee_connection(
    mut stream: TcpStream,
    _node: Arc<Node>,
    target: String,
    prekey_store: Arc<RwLock<PreKeyStore>>,
    sessions: Arc<RwLock<HashMap<String, E2EESession>>>,
) -> Result<(), ProxyError> {
    info!("Establishing E2EE session for connection to {}", target);

    let session_id = establish_e2ee_session(&mut stream, &prekey_store, &sessions).await?;

    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
    info!("E2EE handshake complete, session: {}", session_id);

    let mut target_stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
            return Err(ProxyError::Io(e));
        }
    };

    let mut buf = [0u8; 65535];
    let mut len_buf = [0u8; 4];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        let mut offset = 0;
        while offset < n {
            let msg_type = buf[offset];
            offset += 1;

            if msg_type == MSG_TYPE_ENCRYPTED_DATA {
                if offset + 4 > n {
                    break;
                }
                len_buf.copy_from_slice(&buf[offset..offset + 4]);
                let msg_len = u32::from_be_bytes(len_buf) as usize;
                offset += 4;

                if offset + msg_len > n {
                    break;
                }

                let encrypted_data = &buf[offset..offset + msg_len];
                offset += msg_len;

                let mut sessions_guard = sessions.write().await;
                if let Some(e2ee) = sessions_guard.get_mut(&session_id) {
                    if let Ok(session_msg) = serde_json::from_slice::<SessionMessage>(encrypted_data) {
                        if let Ok(decrypted) = e2ee.session.decrypt(&session_msg) {
                            target_stream.write_all(&decrypted).await?;
                        }
                    }
                }
            } else {
                target_stream.write_all(&buf[offset..n]).await?;
                break;
            }
        }

        let resp_buf = &mut [0u8; 65535];
        let resp_n = target_stream.read(resp_buf).await?;
        if resp_n == 0 {
            break;
        }

        let mut sessions_guard = sessions.write().await;
        if let Some(e2ee) = sessions_guard.get_mut(&session_id) {
            if let Ok(encrypted) = e2ee.session.encrypt(&resp_buf[..resp_n]) {
                if let Ok(serialized) = serde_json::to_vec(&encrypted) {
                    let len = (serialized.len() as u32).to_be_bytes();
                    let mut msg = vec![MSG_TYPE_ENCRYPTED_DATA];
                    msg.extend_from_slice(&len);
                    msg.extend_from_slice(&serialized);
                    stream.write_all(&msg).await?;
                    continue;
                }
            }
        }
        stream.write_all(&resp_buf[..resp_n]).await?;
    }

    let mut sessions = sessions.write().await;
    sessions.remove(&session_id);
    info!("E2EE session {} closed", session_id);

    Ok(())
}

async fn establish_e2ee_session(
    stream: &mut TcpStream,
    prekey_store: &Arc<RwLock<PreKeyStore>>,
    sessions: &Arc<RwLock<HashMap<String, E2EESession>>>,
) -> Result<String, ProxyError> {
    let mut msg_type = [0u8; 1];
    stream.read_exact(&mut msg_type).await?;

    if msg_type[0] != MSG_TYPE_PREKEY_REQUEST {
        stream.write_all(&[MSG_TYPE_SESSION_ERROR, 0x01]).await?;
        return Err(ProxyError::InvalidE2EEMessage("Expected prekey request".to_string()));
    }

    let prekey_bundle = {
        let store = prekey_store.read().await;
        store.get_prekey_bundle()
    };

    let bundle_json = serde_json::to_vec(&prekey_bundle)
        .map_err(|e| ProxyError::InvalidE2EEMessage(e.to_string()))?;
    let bundle_len = (bundle_json.len() as u32).to_be_bytes();

    let mut response = vec![MSG_TYPE_PREKEY_RESPONSE];
    response.extend_from_slice(&bundle_len);
    response.extend_from_slice(&bundle_json);
    stream.write_all(&response).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let session_msg_len = u32::from_be_bytes(len_buf) as usize;

    let mut session_buf = vec![0u8; session_msg_len];
    stream.read_exact(&mut session_buf).await?;

    let session_msg: SessionMessage = serde_json::from_slice(&session_buf)
        .map_err(|e| ProxyError::InvalidE2EEMessage(e.to_string()))?;

    let mut store = prekey_store.write().await;
    let initiator_identity = if let vigilnet_crypto::session::MessageType::X3DHPreKey { 
        identity_key, .. 
    } = &session_msg.message_type {
        *identity_key
    } else {
        return Err(ProxyError::InvalidE2EEMessage("Expected X3DH prekey message".to_string()));
    };

    let (spk_id, otpk_id) = if let vigilnet_crypto::session::MessageType::X3DHPreKey { 
        spk_id, otpk_id, .. 
    } = &session_msg.message_type {
        (*spk_id, *otpk_id)
    } else {
        (0, None)
    };

    let one_time_prekey = if let Some(id) = otpk_id {
        store.consume_one_time_prekey(id)
    } else {
        None
    };

    let session = Session::create_responder(
        store.identity_key(),
        store.signed_prekey(),
        one_time_prekey.as_ref(),
        initiator_identity,
        initiator_identity,
        spk_id,
        otpk_id,
    )?;

    let session_id = session.session_id().to_string();
    let peer_identity = session.peer_identity();

    let e2ee_session = E2EESession {
        session,
        peer_identity,
    };

    {
        let mut session_map = sessions.write().await;
        session_map.insert(session_id.clone(), e2ee_session);
    }

    let ack = vec![MSG_TYPE_PREKEY_RESPONSE, 0x00, 0x00, 0x00, 0x00];
    stream.write_all(&ack).await?;

    info!("E2EE session established: {}", session_id);
    Ok(session_id)
}

async fn handle_plain_connection(
    mut stream: TcpStream,
    node: Arc<Node>,
    target: String,
) -> Result<(), ProxyError> {
    match node.build_circuit().await {
        Ok(circuit_id) => {
            info!("Built circuit {} for connection to {}", circuit_id, target);
            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
            Ok(())
        }
        Err(e) => {
            stream.write_all(&[0x05, 0x04, 0x00, 0x01, 0,0,0,0, 0,0]).await?;
            warn!("Failed to build circuit for {}: {}", target, e);
            Ok(())
        }
    }
}
