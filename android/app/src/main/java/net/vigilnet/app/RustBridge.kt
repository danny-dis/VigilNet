package net.vigilnet.app

class RustBridge {
    companion object {
        init {
            System.loadLibrary("vigilnet_android")
        }
    }

    // Initialize the Rust engine
    external fun init(storagePath: String): Int

    // Shutdown the engine
    external fun shutdown()

    // Backend management
    external fun enableBackend(backendId: Int): Int
    external fun disableBackend(backendId: Int): Int
    external fun switchBackend(backendId: Int): Int

    // VPN management
    external fun setTunFd(fd: Int): Int
    external fun startVpn(): Int
    external fun stopVpn(): Int
    
    // Notify about network changes
    external fun onNetworkChanged(isWifi: Boolean, isMobile: Boolean): Int
    
    // Battery management
    external fun updateBattery(level: Int, charging: Boolean)

    // Tor Configuration
    external fun setTorBridges(bridges: Array<String>)

    // Split Tunneling
    external fun addExcludedApp(packageName: String): Int
    external fun removeExcludedApp(packageName: String): Int
    external fun addExcludedDomain(domain: String): Int
    external fun removeExcludedDomain(domain: String): Int

    // Multi-Hop Routing
    external fun setRoutingChain(chainIds: IntArray): Int

    // Circle Management
    external fun createCircle(name: String, path: String): String
    external fun createInvite(circleId: String, path: String): String
    external fun joinCircle(inviteJson: String, path: String): String
}
