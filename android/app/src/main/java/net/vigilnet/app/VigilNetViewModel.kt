package net.vigilnet.app

import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

enum class BackendType(val id: Int, val displayName: String, val icon: String) {
    CLEARNET(0, "Clearnet", "🌐"),
    TOR(1, "Tor", "🧅"),
    I2P(2, "I2P", "🌀"),
    FREENET(3, "Freenet", "🐇"),
    WIREGUARD(8, "WireGuard", "🛡️"),
    NYM(9, "Nym", "🎭")
}

data class BackendState(
    val type: BackendType,
    val isEnabled: Boolean = false,
    val isConnected: Boolean = false,
    val statusMessage: String = "Disconnected",
    val peerCount: Int = 0,
    val latencyMs: Int? = null
)

data class VigilNetUiState(
    val isVpnRunning: Boolean = false,
    val batteryLevel: Int = 100,
    val isCharging: Boolean = false,
    val backends: List<BackendState> = BackendType.values().map { BackendState(it) },
    val activeChain: List<BackendType> = emptyList(),
    val excludedApps: Set<String> = emptySet(),
    val excludedDomains: Set<String> = emptySet(),
    val torBridges: List<String> = emptyList(),
    val circles: List<String> = emptyList() // Using simplified circle summaries for now
)

class VigilNetViewModel : ViewModel() {
    private val _uiState = mutableStateOf(VigilNetUiState())
    val uiState: State<VigilNetUiState> = _uiState

    private val rustBridge = RustBridge()

    init {
        // Start a background loop to poll status from Rust
        startStatusPolling()
    }

    private fun startStatusPolling() {
        viewModelScope.launch {
            while (true) {
                // In a real app, we'd call an FFI method like vigilnet_get_all_status()
                // For now, let's simulate polling or handle direct updates
                delay(2000)
            }
        }
    }

    fun toggleVpn(onStarted: (Boolean) -> Unit) {
        if (_uiState.value.isVpnRunning) {
            rustBridge.stopVpn()
            _uiState.value = _uiState.value.copy(isVpnRunning = false)
            onStarted(false)
        } else {
            // This usually requires VpnService.prepare() first, which is done in MainActivity
            onStarted(true)
        }
    }

    fun setVpnRunning(running: Boolean) {
        _uiState.value = _uiState.value.copy(isVpnRunning = running)
    }

    fun toggleBackend(backend: BackendType) {
        val currentState = _uiState.value.backends.find { it.type == backend } ?: return
        if (currentState.isEnabled) {
            rustBridge.disableBackend(backend.id)
        } else {
            rustBridge.enableBackend(backend.id)
        }
        
        // Update local state (optimistic)
        _uiState.value = _uiState.value.copy(
            backends = _uiState.value.backends.map {
                if (it.type == backend) it.copy(isEnabled = !it.isEnabled) else it
            }
        )
    }

    fun updateBattery(level: Int, charging: Boolean) {
        _uiState.value = _uiState.value.copy(batteryLevel = level, isCharging = charging)
    }

    // Split Tunneling logic
    fun addExcludedApp(packageName: String) {
        rustBridge.addExcludedApp(packageName)
        _uiState.value = _uiState.value.copy(
            excludedApps = _uiState.value.excludedApps + packageName
        )
    }

    fun removeExcludedApp(packageName: String) {
        rustBridge.removeExcludedApp(packageName)
        _uiState.value = _uiState.value.copy(
            excludedApps = _uiState.value.excludedApps - packageName
        )
    }

    // Proxy / Bridge logic
    fun updateTorBridges(bridges: List<String>) {
        rustBridge.setTorBridges(bridges.toTypedArray())
        _uiState.value = _uiState.value.copy(torBridges = bridges)
    }

    // Circle management logic
    fun createCircle(name: String, storagePath: String) {
        val circleId = rustBridge.createCircle(name, storagePath)
        _uiState.value = _uiState.value.copy(
            circles = _uiState.value.circles + "Circle: $name ($circleId)"
        )
    }

    fun joinCircle(inviteJson: String, storagePath: String) {
        val result = rustBridge.joinCircle(inviteJson, storagePath)
        _uiState.value = _uiState.value.copy(
            circles = _uiState.value.circles + "Joined Circle: $result"
        )
    }
}
