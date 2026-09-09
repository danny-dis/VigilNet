package com.vigilnet.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.vigilnet.ffi.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.util.*

/**
 * ViewModel for connection and VPN state management
 */
class ConnectionViewModel : ViewModel() {
    
    private val _connectionState = MutableStateFlow<ConnectionState>(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()
    
    private val _selectedBackend = MutableStateFlow(NetworkBackend.CLEARNET)
    val selectedBackend: StateFlow<Int> = _selectedBackend.asStateFlow()
    
    private val _tunnelStats = MutableStateFlow(TunnelStats(0, 0, 0, 0, 0))
    val tunnelStats: StateFlow<TunnelStats> = _tunnelStats.asStateFlow()
    
    private val _networkStatuses = MutableStateFlow<List<NetworkStatus>>(emptyList())
    val networkStatuses: StateFlow<List<NetworkStatus>> = _networkStatuses.asStateFlow()
    
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()
    
    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()
    
    private val _routingChain = MutableStateFlow<List<Int>>(emptyList())
    val routingChain: StateFlow<List<Int>> = _routingChain.asStateFlow()
    
    private val statsJob: Job? = null
    
    init {
        loadNetworkStatuses()
        startStatsCollection()
    }
    
    fun connect() {
        viewModelScope.launch {
            _isLoading.value = true
            _errorMessage.value = null
            _connectionState.value = ConnectionState.CONNECTING
            
            try {
                // Enable the selected backend
                val result = RustBridge.enableBackend(_selectedBackend.value)
                if (result != 0) {
                    _connectionState.value = ConnectionState.ERROR
                    _errorMessage.value = "Failed to enable network backend"
                    return@launch
                }
                
                _connectionState.value = ConnectionState.CONNECTED
            } catch (e: Exception) {
                _connectionState.value = ConnectionState.ERROR
                _errorMessage.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun disconnect() {
        viewModelScope.launch {
            _isLoading.value = true
            
            // Disable all backends
            NetworkBackend::class.java.declaredFields
                .filter { it.name != "INSTANCE" }
                .forEach { _ ->
                    RustBridge.disableBackend(_selectedBackend.value)
                }
            
            _connectionState.value = ConnectionState.DISCONNECTED
            _isLoading.value = false
        }
    }
    
    fun selectBackend(backendId: Int) {
        _selectedBackend.value = backendId
        
        if (_connectionState.value == ConnectionState.CONNECTED) {
            // Switch backend if already connected
            viewModelScope.launch {
                _isLoading.value = true
                val result = RustBridge.switchBackend(backendId)
                if (result != 0) {
                    _errorMessage.value = "Failed to switch backend"
                }
                _isLoading.value = false
            }
        }
    }
    
    fun enableBackend(backendId: Int) {
        viewModelScope.launch {
            val result = RustBridge.enableBackend(backendId)
            if (result != 0) {
                _errorMessage.value = "Failed to enable ${NetworkBackend.getDisplayName(backendId)}"
            } else {
                updateNetworkStatus(backendId, enabled = true)
            }
        }
    }
    
    fun disableBackend(backendId: Int) {
        viewModelScope.launch {
            val result = RustBridge.disableBackend(backendId)
            if (result != 0) {
                _errorMessage.value = "Failed to disable ${NetworkBackend.getDisplayName(backendId)}"
            } else {
                updateNetworkStatus(backendId, enabled = false)
            }
        }
    }
    
    fun setRoutingChain(chain: List<Int>) {
        _routingChain.value = chain
        
        viewModelScope.launch {
            val result = RustBridge.setRoutingChain(chain.toIntArray())
            if (result != 0) {
                _errorMessage.value = "Failed to set routing chain"
            }
        }
    }
    
    fun addToRoutingChain(backendId: Int) {
        if (!_routingChain.value.contains(backendId)) {
            val newChain = _routingChain.value + backendId
            setRoutingChain(newChain)
        }
    }
    
    fun removeFromRoutingChain(backendId: Int) {
        val newChain = _routingChain.value.filter { it != backendId }
        setRoutingChain(newChain)
    }
    
    fun clearRoutingChain() {
        setRoutingChain(emptyList())
    }
    
    private fun loadNetworkStatuses() {
        // Initialize with default statuses for all backends
        val statuses = (0..11).map { backendId ->
            NetworkStatus(
                backendId = backendId,
                enabled = backendId == NetworkBackend.CLEARNET,
                connected = false,
                peerCount = 0,
                latencyMs = null,
                bytesSent = 0,
                bytesReceived = 0,
                statusMessage = if (backendId == NetworkBackend.CLEARNET) "Ready" else "Not initialized"
            )
        }
        _networkStatuses.value = statuses
    }
    
    private fun updateNetworkStatus(backendId: Int, enabled: Boolean? = null, connected: Boolean? = null) {
        _networkStatuses.value = _networkStatuses.value.map { status ->
            if (status.backendId == backendId) {
                status.copy(
                    enabled = enabled ?: status.enabled,
                    connected = connected ?: status.connected
                )
            } else {
                status
            }
        }
    }
    
    private fun startStatsCollection() {
        viewModelScope.launch {
            while (isActive) {
                if (_connectionState.value == ConnectionState.CONNECTED) {
                    // In a real implementation, these would come from RustBridge
                    _tunnelStats.value = _tunnelStats.value.copy(
                        bytesSent = _tunnelStats.value.bytesSent + (0..1000).random(),
                        bytesReceived = _tunnelStats.value.bytesReceived + (0..1000).random(),
                        packetsSent = _tunnelStats.value.packetsSent + 10,
                        packetsReceived = _tunnelStats.value.packetsReceived + 10
                    )
                }
                delay(1000)
            }
        }
    }
    
    fun clearError() {
        _errorMessage.value = null
    }
    
    override fun onCleared() {
        super.onCleared()
        statsJob?.cancel()
    }
}
