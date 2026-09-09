package com.vigilnet.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.vigilnet.ffi.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.util.*

/**
 * ViewModel for circle management
 */
class CircleViewModel : ViewModel() {
    
    private val _circles = MutableStateFlow<List<CircleInfo>>(emptyList())
    val circles: StateFlow<List<CircleInfo>> = _circles.asStateFlow()
    
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()
    
    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()
    
    private val _showCreateDialog = MutableStateFlow(false)
    val showCreateDialog: StateFlow<Boolean> = _showCreateDialog.asStateFlow()
    
    private val _showJoinDialog = MutableStateFlow(false)
    val showJoinDialog: StateFlow<Boolean> = _showJoinDialog.asStateFlow()
    
    private val _selectedCircle = MutableStateFlow<CircleInfo?>(null)
    val selectedCircle: StateFlow<CircleInfo?> = _selectedCircle.asStateFlow()
    
    private val _inviteCode = MutableStateFlow<String?>(null)
    val inviteCode: StateFlow<String?> = _inviteCode.asStateFlow()
    
    init {
        // Load mock circles for demonstration
        loadMockCircles()
    }
    
    private fun loadMockCircles() {
        _circles.value = listOf(
            CircleInfo(
                id = UUID.randomUUID().toString(),
                name = "Privacy Advocates",
                type = CircleType.PUBLIC,
                memberCount = 12,
                maxMembers = 50,
                createdAt = System.currentTimeMillis() - 86400000 * 7
            ),
            CircleInfo(
                id = UUID.randomUUID().toString(),
                name = "Research Team Alpha",
                type = CircleType.PRIVATE,
                memberCount = 5,
                maxMembers = 10,
                createdAt = System.currentTimeMillis() - 86400000 * 30
            ),
            CircleInfo(
                id = UUID.randomUUID().toString(),
                name = "Mesh Network NYC",
                type = CircleType.PUBLIC,
                memberCount = 23,
                maxMembers = 100,
                createdAt = System.currentTimeMillis() - 86400000 * 3
            )
        )
    }
    
    fun createCircle(name: String, type: Int, maxMembers: Int) {
        viewModelScope.launch {
            _isLoading.value = true
            _errorMessage.value = null
            
            try {
                // Generate random creator ID and key (in real app, these come from secure storage)
                val creatorId = ByteArray(16).apply { Random().nextBytes(this) }
                val creatorKey = ByteArray(32).apply { Random().nextBytes(this) }
                val circleIdOut = ByteArray(16)
                
                val result = RustBridge.createCircle(
                    name = name,
                    circleType = type,
                    creatorId = creatorId,
                    creatorKey = creatorKey,
                    maxMembers = maxMembers,
                    circleIdOut = circleIdOut
                )
                
                if (result != 0) {
                    _errorMessage.value = "Failed to create circle"
                } else {
                    // Create a local circle info (in real app, parse circleIdOut)
                    val newCircle = CircleInfo(
                        id = UUID.randomUUID().toString(),
                        name = name,
                        type = type,
                        memberCount = 1,
                        maxMembers = maxMembers,
                        createdAt = System.currentTimeMillis()
                    )
                    _circles.value = _circles.value + newCircle
                    _showCreateDialog.value = false
                }
            } catch (e: Exception) {
                _errorMessage.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun createInvite(circleId: String, threshold: Int, numShares: Int, validityHours: Int) {
        viewModelScope.launch {
            _isLoading.value = true
            _errorMessage.value = null
            
            try {
                // Generate issuer ID (in real app, this comes from secure storage)
                val issuerId = ByteArray(16).apply { Random().nextBytes(this) }
                val circleIdBytes = circleId.toByteArray()
                
                val inviteJson = RustBridge.createInvite(
                    circleId = circleIdBytes,
                    threshold = threshold,
                    numShares = numShares,
                    issuerId = issuerId,
                    validityHours = validityHours
                )
                
                if (inviteJson.isEmpty()) {
                    _errorMessage.value = "Failed to create invite"
                } else {
                    _inviteCode.value = inviteJson
                }
            } catch (e: Exception) {
                _errorMessage.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun joinCircle(inviteCode: String) {
        viewModelScope.launch {
            _isLoading.value = true
            _errorMessage.value = null
            
            try {
                // Parse invite code and join circle
                // In real implementation, this would call RustBridge
                
                // Simulate successful join
                val joinedCircle = CircleInfo(
                    id = UUID.randomUUID().toString(),
                    name = "Joined Circle",
                    type = CircleType.PRIVATE,
                    memberCount = 8,
                    maxMembers = 20,
                    createdAt = System.currentTimeMillis()
                )
                _circles.value = _circles.value + joinedCircle
                _showJoinDialog.value = false
            } catch (e: Exception) {
                _errorMessage.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun leaveCircle(circleId: String) {
        _circles.value = _circles.value.filter { it.id != circleId }
        if (_selectedCircle.value?.id == circleId) {
            _selectedCircle.value = null
        }
    }
    
    fun sendToCircle(circleId: String, message: String) {
        viewModelScope.launch {
            // In a real implementation, this would call RustBridge
            // to send encrypted message to all circle members
            _errorMessage.value = null
        }
    }
    
    fun selectCircle(circle: CircleInfo?) {
        _selectedCircle.value = circle
    }
    
    fun showCreateDialog() {
        _showCreateDialog.value = true
    }
    
    fun hideCreateDialog() {
        _showCreateDialog.value = false
    }
    
    fun showJoinDialog() {
        _showJoinDialog.value = true
    }
    
    fun hideJoinDialog() {
        _showJoinDialog.value = false
    }
    
    fun clearInviteCode() {
        _inviteCode.value = null
    }
    
    fun clearError() {
        _errorMessage.value = null
    }
    
    fun getCircleTypeName(type: Int): String {
        return when (type) {
            CircleType.PUBLIC -> "Public"
            CircleType.PRIVATE -> "Private"
            CircleType.AUDIT -> "Audit"
            else -> "Unknown"
        }
    }
    
    fun formatTimestamp(timestamp: Long): String {
        val now = System.currentTimeMillis()
        val diff = now - timestamp
        
        return when {
            diff < 60000 -> "Just now"
            diff < 3600000 -> "${diff / 60000}m ago"
            diff < 86400000 -> "${diff / 3600000}h ago"
            diff < 604800000 -> "${diff / 86400000}d ago"
            else -> "${diff / 604800000}w ago"
        }
    }
}
