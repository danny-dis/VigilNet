package com.vigilnet.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.vigilnet.MainActivity
import com.vigilnet.R
import com.vigilnet.ffi.RustBridge
import kotlinx.coroutines.*

/**
 * VigilNet VPN Service
 * 
 * Android VpnService implementation that integrates with Rust native code
 * for multi-network routing, Tor, I2P, WireGuard, and mesh networking.
 */
class VigilNetVpnService : VpnService() {
    
    companion object {
        private const val TAG = "VigilNetVpnService"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "vigilnet_vpn_channel"
        private const val VPN_MTU = 1500
        
        const val ACTION_START = "com.vigilnet.START_VPN"
        const val ACTION_STOP = "com.vigilnet.STOP_VPN"
        
        @Volatile
        var isRunning = false
            private set
    }
    
    private val binder = LocalBinder()
    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val statsScope = CoroutineScope(Dispatchers.IO)
    
    // Stats tracking
    private var bytesSent = 0L
    private var bytesReceived = 0L
    
    inner class LocalBinder : Binder() {
        fun getService(): VigilNetVpnService = this@VigilNetVpnService
    }
    
    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "VPN Service created")
        createNotificationChannel()
        
        // Initialize Rust backend
        val storagePath = getExternalFilesDir(null)?.absolutePath 
            ?: filesDir.absolutePath
        val result = RustBridge.init(storagePath)
        Log.d(TAG, "Rust bridge initialized: $result")
    }
    
    override fun onBind(intent: Intent?): IBinder {
        return binder
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                Log.d(TAG, "Starting VPN service")
                startVpn()
            }
            ACTION_STOP -> {
                Log.d(TAG, "Stopping VPN service")
                stopVpn()
            }
        }
        return START_STICKY
    }
    
    private fun startVpn(): Boolean {
        if (vpnInterface != null) {
            Log.w(TAG, "VPN already running")
            return true
        }
        
        try {
            // Build VPN configuration
            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .setMtu(VPN_MTU)
                .addAddress("10.0.0.2", 24)
                .addDnsServer("1.1.1.1")
                .addDnsServer("1.0.0.1")
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .allowFamily(android.system.OsConstants.AF_INET)
                .allowFamily(android.system.OsConstants.AF_INET6)
            
            // Add excluded apps (split tunneling)
            val excludedApps = getExcludedApps()
            excludedApps.forEach { packageName ->
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (e: Exception) {
                    Log.w(TAG, "Could not exclude app: $packageName")
                }
            }
            
            // Establish VPN connection
            vpnInterface = builder.establish()
            
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                return false
            }
            
            val fd = vpnInterface!!.fd
            Log.d(TAG, "VPN interface established, fd: $fd")
            
            // Pass TUN fd to Rust
            val result = RustBridge.setTunFd(fd)
            if (result != 0) {
                Log.e(TAG, "Failed to set TUN fd in Rust: $result")
                stopVpn()
                return false
            }
            
            // Start VPN in Rust
            val startResult = RustBridge.startVpn()
            if (startResult != 0) {
                Log.e(TAG, "Failed to start VPN in Rust: $startResult")
                stopVpn()
                return false
            }
            
            // Start as foreground service
            startForeground(NOTIFICATION_ID, createNotification())
            isRunning = true
            
            // Start stats collection
            startStatsCollection()
            
            // Start battery monitoring
            startBatteryMonitoring()
            
            Log.i(TAG, "VPN started successfully")
            return true
            
        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN", e)
            stopVpn()
            return false
        }
    }
    
    private fun stopVpn() {
        isRunning = false
        
        // Stop VPN in Rust
        RustBridge.stopVpn()
        
        // Close VPN interface
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null
        
        // Stop foreground service
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        
        Log.i(TAG, "VPN stopped")
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VigilNet VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VigilNet VPN connection status"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        
        val stopIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, VigilNetVpnService::class.java).apply {
                action = ACTION_STOP
            },
            PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("VigilNet VPN")
            .setContentText("Connected - Routing through secure network")
            .setSmallIcon(R.drawable.ic_vpn_connected)
            .setContentIntent(pendingIntent)
            .addAction(R.drawable.ic_stop, "Disconnect", stopIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }
    
    private fun startStatsCollection() {
        statsScope.launch {
            while (isRunning) {
                // Update stats periodically
                delay(1000)
            }
        }
    }
    
    private fun startBatteryMonitoring() {
        serviceScope.launch {
            while (isRunning) {
                val batteryStatus = registerReceiver(null, 
                    android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED)
                )
                
                batteryStatus?.let { intent ->
                    val level = intent.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, -1)
                    val scale = intent.getIntExtra(android.os.BatteryManager.EXTRA_SCALE, -1)
                    val status = intent.getIntExtra(android.os.BatteryManager.EXTRA_STATUS, -1)
                    
                    val batteryPct = (level * 100 / scale.toFloat()).toInt()
                    val isCharging = status == android.os.BatteryManager.BATTERY_STATUS_CHARGING ||
                            status == android.os.BatteryManager.BATTERY_STATUS_FULL
                    
                    RustBridge.updateBattery(batteryPct, isCharging)
                }
                
                delay(30000) // Check battery every 30 seconds
            }
        }
    }
    
    private fun getExcludedApps(): List<String> {
        // Load from preferences
        val prefs = getSharedPreferences("vigilnet_prefs", MODE_PRIVATE)
        return prefs.getStringSet("excluded_apps", emptySet())?.toList() ?: emptyList()
    }
    
    fun addExcludedApp(packageName: String) {
        RustBridge.addExcludedApp(packageName)
        
        val prefs = getSharedPreferences("vigilnet_prefs", MODE_PRIVATE)
        val current = prefs.getStringSet("excluded_apps", mutableSetOf())?.toMutableSet() 
            ?: mutableSetOf()
        current.add(packageName)
        prefs.edit().putStringSet("excluded_apps", current).apply()
    }
    
    fun removeExcludedApp(packageName: String) {
        RustBridge.removeExcludedApp(packageName)
        
        val prefs = getSharedPreferences("vigilnet_prefs", MODE_PRIVATE)
        val current = prefs.getStringSet("excluded_apps", mutableSetOf())?.toMutableSet() 
            ?: mutableSetOf()
        current.remove(packageName)
        prefs.edit().putStringSet("excluded_apps", current).apply()
    }
    
    fun getCurrentStats(): TunnelStats {
        return TunnelStats(
            bytesSent = bytesSent,
            bytesReceived = bytesReceived,
            packetsSent = 0,
            packetsReceived = 0,
            activeConnections = 0
        )
    }
    
    override fun onDestroy() {
        super.onDestroy()
        stopVpn()
        RustBridge.shutdown()
        serviceScope.cancel()
        statsScope.cancel()
        Log.d(TAG, "VPN Service destroyed")
    }
    
    // Called when network changes (WiFi <-> Mobile)
    fun onNetworkChanged(isWifi: Boolean, isMobile: Boolean) {
        serviceScope.launch {
            RustBridge.onNetworkChanged(isWifi, isMobile)
        }
    }
}

/**
 * Data class for tunnel statistics
 */
data class TunnelStats(
    val bytesSent: Long,
    val bytesReceived: Long,
    val packetsSent: Long,
    val packetsReceived: Long,
    val activeConnections: Int
)
