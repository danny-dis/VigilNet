package net.vigilnet.app

class RustBridge {
    companion object {
        init {
            System.loadLibrary("vigilnet_android")
        }
    }

    // Initialize the Rust engine
    external fun init(): Int

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
    
    // Battery management
    external fun updateBattery(level: Int, charging: Boolean)
}
