//! FFI / JNI Bridge
//!
//! Provides the C-compatible FFI interface for calling Rust code
//! from Kotlin/Java on Android via JNI.
//!
//! When the `android` feature is enabled, this module exposes JNI
//! native methods that the Android app's Kotlin layer calls.

use std::sync::{Arc, OnceLock};
use tokio::runtime::Runtime;
use tracing::info;

use crate::network_manager::{NetworkBackend, NetworkManager};
use crate::vpn_service::VpnTunnel;
use crate::battery::BatteryScheduler;

/// Global state holder for the Android app
/// 
/// Uses OnceLock for thread-safe, one-time initialization.
/// Access is synchronized via Arc.
static APP_STATE: OnceLock<Arc<AppState>> = OnceLock::new();

/// Application state visible to JNI
struct AppState {
    runtime: Runtime,
    network_manager: tokio::sync::RwLock<NetworkManager>,
    vpn_tunnel: tokio::sync::RwLock<VpnTunnel>,
    battery: tokio::sync::RwLock<BatteryScheduler>,
    circles: Arc<vigilnet_agent_circles::CirclesService>,
}

impl AppState {
    fn new() -> Self {
        let runtime = Runtime::new().expect("Failed to create Tokio runtime");
        Self {
            runtime,
            network_manager: tokio::sync::RwLock::new(NetworkManager::new()),
            vpn_tunnel: tokio::sync::RwLock::new(VpnTunnel::new()),
            battery: tokio::sync::RwLock::new(BatteryScheduler::new()),
            circles: Arc::new(vigilnet_agent_circles::CirclesService::new()),
        }
    }
}

/// Safe accessor for APP_STATE
/// 
/// Returns Some(state) if initialized, None otherwise
fn get_app_state() -> Option<Arc<AppState>> {
    APP_STATE.get().cloned()
}

/// Initialize the global app state
/// 
/// Thread-safe - only the first call succeeds
fn init_app_state() -> Arc<AppState> {
    APP_STATE.get_or_init(|| {
        let state = Arc::new(AppState::new());
        
        // Channel wiring
        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel(1024);
        let (nm_tx, nm_rx) = tokio::sync::mpsc::channel(1024);

        // Configure components
        state.runtime.block_on(async {
            state.network_manager.write().await.set_tun_sender(nm_tx);
            state.vpn_tunnel.write().await.set_channels(tun_tx, nm_rx);
        });

        // Spawn packet glue task (TUN -> NetworkManager)
        let state_clone = state.clone();
        state.runtime.spawn(async move {
            info!("Starting batched packet handler loop");
            let mut batch = Vec::with_capacity(32);
            while let Some(packet) = tun_rx.recv().await {
                batch.push(packet);
                
                // Try to collect more packets that are already in the channel
                while batch.len() < 32 {
                    match tun_rx.try_recv() {
                        Ok(p) => batch.push(p),
                        Err(_) => break,
                    }
                }

                // Process the batch
                let nm = state_clone.network_manager.read().await;
                for p in batch.drain(..) {
                    nm.handle_packet(p).await;
                }
            }
            info!("Packet handler loop exited");
        });

        state
    }).clone()
}

// ========================================================================
// C FFI Functions (platform-independent, for use with UniFFI or manual FFI)
// ========================================================================

/// C-compatible initialization with storage path.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn vigilnet_init_with_path(storage_path: *const std::os::raw::c_char) -> i32 {
    let res = vigilnet_init();
    if res != 0 { return res; }
    
    if !storage_path.is_null() {
        let path = match unsafe { std::ffi::CStr::from_ptr(storage_path).to_str() } {
            Ok(s) => s.to_string(),
            Err(_) => return -1,
        };
        
        let Some(state) = get_app_state() else {
            return -1;
        };
        
        state.runtime.block_on(async {
            state.network_manager.write().await.set_storage_path(path).await;
        });
    }
    
    0
}

/// Initialize the VigilNet engine
/// 
/// Must be called once before any other function.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn vigilnet_init() -> i32 {
    // Initialize tracing
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .try_init();

    info!("Initializing VigilNet engine");

    // Initialize app state (thread-safe, idempotent)
    let _ = init_app_state();

    info!("VigilNet engine initialized successfully");
    0
}

/// Shutdown the VigilNet engine
#[no_mangle]
pub extern "C" fn vigilnet_shutdown() {
    info!("Shutting down VigilNet engine");
    // OnceLock cannot be reset, but we can signal shutdown
    // The runtime will be dropped when APP_STATE is dropped
}

/// Helper function to convert backend_id to NetworkBackend
fn backend_from_id(backend_id: i32) -> Option<NetworkBackend> {
    match backend_id {
        0 => Some(NetworkBackend::Clearnet),
        1 => Some(NetworkBackend::Tor),
        2 => Some(NetworkBackend::I2p),
        3 => Some(NetworkBackend::Freenet),
        4 => Some(NetworkBackend::Yggdrasil),
        5 => Some(NetworkBackend::Lokinet),
        6 => Some(NetworkBackend::GnuNet),
        7 => Some(NetworkBackend::Cjdns),
        8 => Some(NetworkBackend::WireGuard),
        9 => Some(NetworkBackend::Nym),
        10 => Some(NetworkBackend::Ipfs),
        11 => Some(NetworkBackend::ZeroNet),
        _ => None,
    }
}

/// Enable a network backend by index
/// 
/// Backend indices:
/// 0=Clearnet, 1=Tor, 2=I2P, 3=Freenet, 4=Yggdrasil,
/// 5=Lokinet, 6=GNUnet, 7=CJDNS, 8=WireGuard, 9=Nym,
/// 10=IPFS, 11=ZeroNet
///
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn vigilnet_enable_backend(backend_id: i32) -> i32 {
    let Some(backend) = backend_from_id(backend_id) else {
        return -1;
    };

    let Some(state) = get_app_state() else {
        tracing::error!("VigilNet not initialized");
        return -1;
    };

    state.runtime.block_on(async {
        match state.network_manager.write().await.enable_backend(backend).await {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("Failed to enable backend: {}", e);
                -1
            }
        }
    })
}

/// Disable a network backend by index
#[no_mangle]
pub extern "C" fn vigilnet_disable_backend(backend_id: i32) -> i32 {
    let Some(backend) = backend_from_id(backend_id) else {
        return -1;
    };

    let Some(state) = get_app_state() else {
        tracing::error!("VigilNet not initialized");
        return -1;
    };

    state.runtime.block_on(async {
        match state.network_manager.write().await.disable_backend(backend).await {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("Failed to disable backend: {}", e);
                -1
            }
        }
    })
}

/// Switch to a new default backend (Make-Before-Break)
#[no_mangle]
pub extern "C" fn vigilnet_switch_backend(backend_id: i32) -> i32 {
    let Some(backend) = backend_from_id(backend_id) else {
        return -1;
    };

    let Some(state) = get_app_state() else {
        tracing::error!("VigilNet not initialized");
        return -1;
    };

    state.runtime.block_on(async {
        match state.network_manager.write().await.switch_backend(backend).await {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("Failed to switch backend: {}", e);
                -1
            }
        }
    })
}

/// Set the TUN file descriptor from Android VpnService
///
/// This fd comes from VpnService.Builder.establish() on Android.
/// Returns 0 on success, -1 on error.
#[no_mangle]
pub extern "C" fn vigilnet_set_tun_fd(fd: i32) -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };

    state.runtime.block_on(async {
        let mut tunnel = state.vpn_tunnel.write().await;
        tunnel.set_tun_fd(fd);
        0
    })
}

/// Start the VPN tunnel
#[no_mangle]
pub extern "C" fn vigilnet_start_vpn() -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };

    state.runtime.block_on(async {
        let mut tunnel = state.vpn_tunnel.write().await;
        match tunnel.start().await {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("Failed to start VPN: {}", e);
                -1
            }
        }
    })
}

/// Stop the VPN tunnel
#[no_mangle]
pub extern "C" fn vigilnet_stop_vpn() -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };

    state.runtime.block_on(async {
        let mut tunnel = state.vpn_tunnel.write().await;
        match tunnel.stop().await {
            Ok(()) => 0,
            Err(e) => {
                tracing::error!("Failed to stop VPN: {}", e);
                -1
            }
        }
    })
}

/// Set Tor bridges
/// 
/// Accepts a newline-separated string of bridge lines.
#[no_mangle]
pub extern "C" fn vigilnet_set_tor_bridges(bridges_str: *const std::os::raw::c_char) -> i32 {
    use std::ffi::CStr;
    
    let Some(state) = get_app_state() else {
        return -1;
    };

    if bridges_str.is_null() {
        return -1;
    }

    let c_str = unsafe { CStr::from_ptr(bridges_str) };

    let bridges_string = match c_str.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };

    let bridges: Vec<String> = bridges_string
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    state.runtime.block_on(async {
        state.network_manager.read().await.set_tor_bridges(bridges).await;
        0
    })
}

/// Start Mesh Agent
#[no_mangle]
pub extern "C" fn vigilnet_start_mesh() -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };
    
    state.runtime.block_on(async {
        match state.network_manager.read().await.start_mesh().await {
            Ok(_) => 0,
            Err(e) => {
                tracing::error!("Failed to start mesh: {}", e);
                -1
            }
        }
    })
}

/// Stop Mesh Agent
#[no_mangle]
pub extern "C" fn vigilnet_stop_mesh() -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };
    
    state.runtime.block_on(async {
        match state.network_manager.read().await.stop_mesh().await {
            Ok(_) => 0,
            Err(e) => {
                tracing::error!("Failed to stop mesh: {}", e);
                -1
            }
        }
    })
}

/// Create a new trust circle
/// 
/// Returns 0 on success, -1 on error.
/// circle_id_out should be a pointer to a 16-byte buffer for the UUID.
#[no_mangle]
pub extern "C" fn vigilnet_create_circle(
    name: *const std::os::raw::c_char,
    circle_type: i32,
    creator_id_ptr: *const u8,
    creator_key_ptr: *const u8,
    max_members: usize,
    circle_id_out: *mut u8,
) -> i32 {
    use std::ffi::CStr;
    use uuid::Uuid;

    let Some(state) = get_app_state() else {
        return -1;
    };

    if name.is_null() || creator_id_ptr.is_null() || creator_key_ptr.is_null() {
        return -1;
    }

    let name = match unsafe { CStr::from_ptr(name).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };

    let creator_id = unsafe {
        let bytes = std::slice::from_raw_parts(creator_id_ptr, 16);
        Uuid::from_slice(bytes).unwrap_or_else(|_| Uuid::nil())
    };

    let creator_key = unsafe {
        let mut key = [0u8; 32];
        key.copy_from_slice(std::slice::from_raw_parts(creator_key_ptr, 32));
        key
    };

    let c_type = match circle_type {
        0 => vigilnet_agent_circles::CircleType::Public,
        1 => vigilnet_agent_circles::CircleType::Private,
        2 => vigilnet_agent_circles::CircleType::Audit,
        _ => return -1,
    };

    state.runtime.block_on(async {
        match state.circles.create_circle(name, c_type, creator_id, creator_key, max_members).await {
            Ok(uuid) => {
                if !circle_id_out.is_null() {
                    unsafe {
                        circle_id_out.copy_from(uuid.as_bytes().as_ptr(), 16);
                    }
                }
                0
            }
            Err(e) => {
                tracing::error!("Failed to create circle: {}", e);
                -1
            }
        }
    })
}

/// Create an invite for a circle
/// 
/// Returns 0 on success, -1 on error.
/// invite_json_out will receive a JSON string of the invite (must be freed by caller).
#[no_mangle]
pub extern "C" fn vigilnet_create_invite(
    circle_id_ptr: *const u8,
    threshold: u8,
    num_shares: u8,
    issuer_id_ptr: *const u8,
    validity_hours: i64,
    invite_json_out: *mut *mut std::os::raw::c_char,
) -> i32 {
    use uuid::Uuid;
    use std::ffi::CString;

    let Some(state) = get_app_state() else {
        return -1;
    };

    if circle_id_ptr.is_null() || issuer_id_ptr.is_null() {
        return -1;
    }

    let circle_id = unsafe {
        Uuid::from_slice(std::slice::from_raw_parts(circle_id_ptr, 16))
            .unwrap_or_else(|_| Uuid::nil())
    };

    let issuer_id = unsafe {
        Uuid::from_slice(std::slice::from_raw_parts(issuer_id_ptr, 16))
            .unwrap_or_else(|_| Uuid::nil())
    };

    state.runtime.block_on(async {
        match state.circles.create_invite(circle_id, threshold, num_shares, issuer_id, None, validity_hours).await {
            Ok(invite) => {
                if !invite_json_out.is_null() {
                    if let Ok(json) = serde_json::to_string(&invite) {
                        if let Ok(c_str) = CString::new(json) {
                            unsafe {
                                *invite_json_out = c_str.into_raw();
                            }
                        }
                    }
                }
                0
            }
            Err(e) => {
                tracing::error!("Failed to create invite: {}", e);
                -1
            }
        }
    })
}

/// Update battery status from Android
#[no_mangle]
pub extern "C" fn vigilnet_update_battery(level: i32, charging: i32) {
    let Some(state) = get_app_state() else {
        return;
    };
    
    state.runtime.block_on(async {
        let mut battery = state.battery.write().await;
        battery.update_battery(level as u8, charging != 0);
    });
}

/// Add an app to the split-tunnel exclusion list
#[no_mangle]
pub extern "C" fn vigilnet_add_excluded_app(package_name: *const std::os::raw::c_char) -> i32 {
    use std::ffi::CStr;
    
    let Some(state) = get_app_state() else {
        return -1;
    };
    
    if package_name.is_null() {
        return -1;
    }
    
    let pkg = match unsafe { CStr::from_ptr(package_name).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    
    state.runtime.block_on(async {
        state.network_manager.read().await.add_excluded_app(pkg).await;
        0
    })
}

/// Remove an app from the split-tunnel exclusion list
#[no_mangle]
pub extern "C" fn vigilnet_remove_excluded_app(package_name: *const std::os::raw::c_char) -> i32 {
    use std::ffi::CStr;
    
    let Some(state) = get_app_state() else {
        return -1;
    };
    
    if package_name.is_null() {
        return -1;
    }
    
    let pkg = match unsafe { CStr::from_ptr(package_name).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    
    state.runtime.block_on(async {
        state.network_manager.read().await.remove_excluded_app(&pkg).await;
        0
    })
}

/// Add a domain to the split-tunnel exclusion list
#[no_mangle]
pub extern "C" fn vigilnet_add_excluded_domain(domain: *const std::os::raw::c_char) -> i32 {
    use std::ffi::CStr;
    
    let Some(state) = get_app_state() else {
        return -1;
    };
    
    if domain.is_null() {
        return -1;
    }
    
    let dom = match unsafe { CStr::from_ptr(domain).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    
    state.runtime.block_on(async {
        state.network_manager.read().await.add_excluded_domain(dom).await;
        0
    })
}

/// Remove a domain from the split-tunnel exclusion list
#[no_mangle]
pub extern "C" fn vigilnet_remove_excluded_domain(domain: *const std::os::raw::c_char) -> i32 {
    use std::ffi::CStr;
    
    let Some(state) = get_app_state() else {
        return -1;
    };
    
    if domain.is_null() {
        return -1;
    }
    
    let dom = match unsafe { CStr::from_ptr(domain).to_str() } {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    
    state.runtime.block_on(async {
        state.network_manager.read().await.remove_excluded_domain(&dom).await;
        0
    })
}

/// Set the global routing chain (multi-hop)
/// 
/// chain_ids: pointer to an array of i32 backend IDs
/// len: number of IDs in the array
#[no_mangle]
pub extern "C" fn vigilnet_set_routing_chain(chain_ids: *const i32, len: usize) -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };
    
    if chain_ids.is_null() && len > 0 {
        return -1;
    }

    let ids = unsafe { std::slice::from_raw_parts(chain_ids, len) };

    let mut backends = Vec::new();
    for &id in ids {
        if let Some(backend) = backend_from_id(id) {
            backends.push(backend);
        }
    }

    let chain = crate::network_manager::NetworkChain { chain: backends };
    
    state.runtime.block_on(async {
        let mut policy = state.network_manager.read().await.get_policy().await;
        policy.default_chain = chain;
        state.network_manager.read().await.set_policy(policy).await;
        0
    })
}

#[no_mangle]
pub extern "C" fn vigilnet_on_network_changed(is_wifi: bool, is_mobile: bool) -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };

    state.runtime.block_on(async {
        let manager = state.network_manager.read().await;
        manager.on_network_changed(is_wifi, is_mobile).await;
    });

    0
}

/// Initialize mobile agents
#[no_mangle]
pub extern "C" fn vigilnet_init_agents(
    enable_mesh: bool,
    enable_circles: bool,
    enable_research: bool,
) -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };

    let config = crate::agents::MobileAgentConfig {
        enable_mesh,
        enable_circles,
        enable_research,
        storage_path: None,
    };

    state.runtime.block_on(async {
        match state.network_manager.read().await.init_agent_manager(config).await {
            Ok(_) => 0,
            Err(e) => {
                tracing::error!("Failed to init agents: {}", e);
                -1
            }
        }
    })
}

/// Start mobile agents
#[no_mangle]
pub extern "C" fn vigilnet_start_agents() -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };

    state.runtime.block_on(async {
        match state.network_manager.read().await.start_agents().await {
            Ok(_) => 0,
            Err(e) => {
                tracing::error!("Failed to start agents: {}", e);
                -1
            }
        }
    })
}

/// Stop mobile agents
#[no_mangle]
pub extern "C" fn vigilnet_stop_agents() -> i32 {
    let Some(state) = get_app_state() else {
        return -1;
    };

    state.runtime.block_on(async {
        match state.network_manager.read().await.stop_agents().await {
            Ok(_) => 0,
            Err(e) => {
                tracing::error!("Failed to stop agents: {}", e);
                -1
            }
        }
    })
}

// ========================================================================
// JNI Functions (Android-specific, only compiled with `android` feature)
// ========================================================================

#[cfg(feature = "android")]
pub mod jni_bridge {
    use jni::JNIEnv;
    use jni::objects::JClass;
    use jni::sys::{jint, jboolean};

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_onNetworkChanged(
        _env: JNIEnv,
        _class: JClass,
        is_wifi: jboolean,
        is_mobile: jboolean,
    ) -> jint {
        super::vigilnet_on_network_changed(is_wifi != 0, is_mobile != 0)
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_init(
        env: JNIEnv,
        _class: JClass,
        storage_path: jni::objects::JString,
    ) -> jint {
        let path: String = match env.get_string(&storage_path) {
            Ok(s) => s.into(),
            Err(_) => return -1,
        };
        
        match std::ffi::CString::new(path) {
            Ok(path_c) => super::vigilnet_init_with_path(path_c.as_ptr()),
            Err(_) => -1,
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_shutdown(
        _env: JNIEnv,
        _class: JClass,
    ) {
        super::vigilnet_shutdown()
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_enableBackend(
        _env: JNIEnv,
        _class: JClass,
        backend_id: jint,
    ) -> jint {
        super::vigilnet_enable_backend(backend_id)
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_disableBackend(
        _env: JNIEnv,
        _class: JClass,
        backend_id: jint,
    ) -> jint {
        super::vigilnet_disable_backend(backend_id)
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_switchBackend(
        _env: JNIEnv,
        _class: JClass,
        backend_id: jint,
    ) -> jint {
        super::vigilnet_switch_backend(backend_id)
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_setTunFd(
        _env: JNIEnv,
        _class: JClass,
        fd: jint,
    ) -> jint {
        super::vigilnet_set_tun_fd(fd)
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_startVpn(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        super::vigilnet_start_vpn()
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_stopVpn(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        super::vigilnet_stop_vpn()
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_updateBattery(
        _env: JNIEnv,
        _class: JClass,
        level: jint,
        charging: jboolean,
    ) {
        super::vigilnet_update_battery(level, charging as i32);
    }
    
    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_setTorBridges(
        env: JNIEnv,
        _class: JClass,
        bridges: jni::objects::JString,
    ) -> jint {
        let bridges_str = match env.get_string(&bridges) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        
        if bridges_str.as_ptr().is_null() {
            return -1;
        }
        
        super::vigilnet_set_tor_bridges(bridges_str.as_ptr())
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_startMesh(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        super::vigilnet_start_mesh()
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_stopMesh(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        super::vigilnet_stop_mesh()
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_createCircle(
        mut env: JNIEnv,
        _class: JClass,
        name: jni::objects::JString,
        circle_type: jint,
        creator_id_bytes: jni::objects::JByteArray,
        creator_key_bytes: jni::objects::JByteArray,
        max_members: jint,
        circle_id_out: jni::objects::JByteArray,
    ) -> jint {
        let name_str: String = match env.get_string(&name) {
            Ok(s) => s.into(),
            Err(_) => return -1,
        };
        
        let name_c = match std::ffi::CString::new(name_str) {
            Ok(c) => c,
            Err(_) => return -1,
        };
        
        let creator_id = match env.convert_byte_array(&creator_id_bytes) {
            Ok(v) if v.len() == 16 => v,
            _ => return -1,
        };
        
        let creator_key = match env.convert_byte_array(&creator_key_bytes) {
            Ok(v) if v.len() == 32 => v,
            _ => return -1,
        };
        
        let mut id_out = [0u8; 16];
        let res = super::vigilnet_create_circle(
            name_c.as_ptr(),
            circle_type,
            creator_id.as_ptr(),
            creator_key.as_ptr(),
            max_members as usize,
            id_out.as_mut_ptr()
        );
        
        if res == 0 {
            let id_i8: Vec<i8> = id_out.iter().map(|&b| b as i8).collect();
            let _ = env.set_byte_array_region(&circle_id_out, 0, &id_i8);
        }
        
        res
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_createInvite(
        env: JNIEnv,
        _class: JClass,
        circle_id_bytes: jni::objects::JByteArray,
        threshold: jint,
        num_shares: jint,
        issuer_id_bytes: jni::objects::JByteArray,
        validity_hours: jint,
    ) -> jni::objects::JString {
        let circle_id = match env.convert_byte_array(&circle_id_bytes) {
            Ok(v) if v.len() == 16 => v,
            _ => return env.new_string("").unwrap_or_else(|_| jni::objects::JString::from(std::ptr::null_mut())),
        };
        
        let issuer_id = match env.convert_byte_array(&issuer_id_bytes) {
            Ok(v) if v.len() == 16 => v,
            _ => return env.new_string("").unwrap_or_else(|_| jni::objects::JString::from(std::ptr::null_mut())),
        };
        
        let mut invite_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
        
        let res = super::vigilnet_create_invite(
            circle_id.as_ptr(),
            threshold as u8,
            num_shares as u8,
            issuer_id.as_ptr(),
            validity_hours as i64,
            &mut invite_ptr
        );
        
        if res == 0 && !invite_ptr.is_null() {
            let json = unsafe {
                let s = std::ffi::CStr::from_ptr(invite_ptr).to_string_lossy().into_owned();
                let _ = std::ffi::CString::from_raw(invite_ptr);
                s
            };
            env.new_string(json).unwrap_or_else(|_| {
                env.new_string("").unwrap_or_else(|_| jni::objects::JString::from(std::ptr::null_mut()))
            })
        } else {
            env.new_string("").unwrap_or_else(|_| jni::objects::JString::from(std::ptr::null_mut()))
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_addExcludedApp(
        env: JNIEnv,
        _class: JClass,
        package_name: jni::objects::JString,
    ) -> jint {
        let pkg: String = match env.get_string(&package_name) {
            Ok(s) => s.into(),
            Err(_) => return -1,
        };
        
        match std::ffi::CString::new(pkg) {
            Ok(pkg_c) => super::vigilnet_add_excluded_app(pkg_c.as_ptr()),
            Err(_) => -1,
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_removeExcludedApp(
        env: JNIEnv,
        _class: JClass,
        package_name: jni::objects::JString,
    ) -> jint {
        let pkg: String = match env.get_string(&package_name) {
            Ok(s) => s.into(),
            Err(_) => return -1,
        };
        
        match std::ffi::CString::new(pkg) {
            Ok(pkg_c) => super::vigilnet_remove_excluded_app(pkg_c.as_ptr()),
            Err(_) => -1,
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_addExcludedDomain(
        env: JNIEnv,
        _class: JClass,
        domain: jni::objects::JString,
    ) -> jint {
        let dom: String = match env.get_string(&domain) {
            Ok(s) => s.into(),
            Err(_) => return -1,
        };
        
        match std::ffi::CString::new(dom) {
            Ok(dom_c) => super::vigilnet_add_excluded_domain(dom_c.as_ptr()),
            Err(_) => -1,
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_removeExcludedDomain(
        env: JNIEnv,
        _class: JClass,
        domain: jni::objects::JString,
    ) -> jint {
        let dom: String = match env.get_string(&domain) {
            Ok(s) => s.into(),
            Err(_) => return -1,
        };
        
        match std::ffi::CString::new(dom) {
            Ok(dom_c) => super::vigilnet_remove_excluded_domain(dom_c.as_ptr()),
            Err(_) => -1,
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_setRoutingChain(
        env: JNIEnv,
        _class: JClass,
        chain_ids: jni::objects::JIntArray,
    ) -> jint {
        let ids = match env.get_int_array_elements(&chain_ids, jni::objects::ReleaseMode::NoCopyBack) {
            Ok(a) => a,
            Err(_) => return -1,
        };
        
        let len = match ids.size() {
            Ok(n) => n as usize,
            Err(_) => return -1,
        };
        
        super::vigilnet_set_routing_chain(ids.as_ptr(), len)
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_initAgents(
        _env: JNIEnv,
        _class: JClass,
        enable_mesh: jboolean,
        enable_circles: jboolean,
        enable_research: jboolean,
    ) -> jint {
        super::vigilnet_init_agents(
            enable_mesh != 0,
            enable_circles != 0,
            enable_research != 0,
        )
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_startAgents(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        super::vigilnet_start_agents()
    }

    #[no_mangle]
    pub extern "system" fn Java_net_vigilnet_app_RustBridge_stopAgents(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        super::vigilnet_stop_agents()
    }
}
