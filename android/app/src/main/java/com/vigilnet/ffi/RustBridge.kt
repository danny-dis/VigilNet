package com.vigilnet.ffi

/**
 * FFI Bridge to Rust native library
 * Maps to the JNI functions in vigilnet-android crate
 */
object RustBridge {
    
    init {
        System.loadLibrary("vigilnet")
    }
    
    // Initialization
    external fun init(storagePath: String): Int
    external fun shutdown()
    
    // Network Backend Management
    external fun enableBackend(backendId: Int): Int
    external fun disableBackend(backendId: Int): Int
    external fun switchBackend(backendId: Int): Int
    
    // VPN Management
    external fun setTunFd(fd: Int): Int
    external fun startVpn(): Int
    external fun stopVpn(): Int
    
    // Battery Management
    external fun updateBattery(level: Int, charging: Boolean)
    
    // Tor Configuration
    external fun setTorBridges(bridges: String): Int
    
    // Mesh Network
    external fun startMesh(): Int
    external fun stopMesh(): Int
    
    // Circles Management
    external fun createCircle(
        name: String,
        circleType: Int,
        creatorId: ByteArray,
        creatorKey: ByteArray,
        maxMembers: Int,
        circleIdOut: ByteArray
    ): Int
    
    external fun createInvite(
        circleId: ByteArray,
        threshold: Int,
        numShares: Int,
        issuerId: ByteArray,
        validityHours: Int
    ): String
    
    // Split Tunneling
    external fun addExcludedApp(packageName: String): Int
    external fun removeExcludedApp(packageName: String): Int
    external fun addExcludedDomain(domain: String): Int
    external fun removeExcludedDomain(domain: String): Int
    
    // Routing Chain
    external fun setRoutingChain(chainIds: IntArray): Int
    
    // Network Change Handling
    external fun onNetworkChanged(isWifi: Boolean, isMobile: Boolean): Int
    
    // Agent Management
    external fun initAgents(
        enableMesh: Boolean,
        enableCircles: Boolean,
        enableResearch: Boolean
    ): Int
    
    external fun startAgents(): Int
    external fun stopAgents(): Int
}

/**
 * Network Backend IDs (must match Rust backend_from_id function)
 */
object NetworkBackend {
    const val CLEARNET = 0
    const val TOR = 1
    const val I2P = 2
    const val FREENET = 3
    const val YGGDRASIL = 4
    const val LOKINET = 5
    const val GNUNET = 6
    const val CJDNS = 7
    const val WIREGUARD = 8
    const val NYM = 9
    const val IPFS = 10
    const val ZERONET = 11
    
    fun getDisplayName(backendId: Int): String {
        return when (backendId) {
            CLEARNET -> "Clearnet (Direct)"
            TOR -> "Tor Network"
            I2P -> "I2P Network"
            FREENET -> "Freenet / Hyphanet"
            YGGDRASIL -> "Yggdrasil Mesh"
            LOKINET -> "Lokinet"
            GNUNET -> "GNUnet"
            CJDNS -> "CJDNS Mesh"
            WIREGUARD -> "WireGuard Tunnel"
            NYM -> "Nym Mixnet"
            IPFS -> "IPFS"
            ZERONET -> "ZeroNet"
            else -> "Unknown"
        }
    }
    
    fun getAnonymityLevel(backendId: Int): Int {
        return when (backendId) {
            CLEARNET -> 0
            WIREGUARD -> 3
            YGGDRASIL -> 4
            CJDNS -> 4
            IPFS -> 3
            ZERONET -> 4
            GNUNET -> 6
            LOKINET -> 7
            FREENET -> 7
            TOR -> 8
            I2P -> 8
            NYM -> 9
            else -> 0
        }
    }
    
    fun isAvailable(backendId: Int): Boolean {
        return when (backendId) {
            CLEARNET, TOR, I2P, FREENET, WIREGUARD, NYM -> true
            else -> false
        }
    }
}

/**
 * Circle Types
 */
object CircleType {
    const val PUBLIC = 0
    const val PRIVATE = 1
    const val AUDIT = 2
}

/**
 * Data classes for FFI communication
 */
data class NetworkStatus(
    val backendId: Int,
    val enabled: Boolean,
    val connected: Boolean,
    val peerCount: Int,
    val latencyMs: Int?,
    val bytesSent: Long,
    val bytesReceived: Long,
    val statusMessage: String
)

data class TunnelStats(
    val bytesSent: Long,
    val bytesReceived: Long,
    val packetsSent: Long,
    val packetsReceived: Long,
    val activeConnections: Int
)

data class CircleInfo(
    val id: String,
    val name: String,
    val type: Int,
    val memberCount: Int,
    val maxMembers: Int,
    val createdAt: Long
)

data class AgentInfo(
    val id: String,
    val name: String,
    val type: AgentType,
    val status: AgentStatus,
    val peerCount: Int,
    val lastActive: Long
)

enum class AgentType {
    MESH,
    CIRCLE,
    RESEARCH
}

enum class AgentStatus {
    STOPPED,
    STARTING,
    RUNNING,
    ERROR
}

enum class ConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
}
