package net.vigilnet.app

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

class VigilNetVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val rustBridge = RustBridge()

    companion object {
        const val TAG = "VigilNetVpnService"
        const val ACTION_START = "net.vigilnet.app.START"
        const val ACTION_STOP = "net.vigilnet.app.STOP"
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "VPN Service created")
        rustBridge.init()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        Log.i(TAG, "Starting VPN")
        if (vpnInterface != null) {
            Log.w(TAG, "VPN already running")
            return
        }

        // Configure the TUN interface
        val builder = Builder()
        builder.setSession("VigilNet")
        builder.addAddress("10.0.0.2", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.setMtu(1500)
        builder.addDnsServer("1.1.1.1")

        // Create the interface
        vpnInterface = builder.establish()

        if (vpnInterface != null) {
            val fd = vpnInterface!!.fd
            Log.i(TAG, "VPN interface established, fd: $fd")
            
            // Pass the fd to Rust
            rustBridge.setTunFd(fd)
            
            // Start the Rust packet loop
            rustBridge.startVpn()
        } else {
            Log.e(TAG, "Failed to establish VPN interface")
        }
    }

    private fun stopVpn() {
        Log.i(TAG, "Stopping VPN")
        rustBridge.stopVpn()
        
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null
        
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
        rustBridge.shutdown()
        Log.i(TAG, "VPN Service destroyed")
    }
}
