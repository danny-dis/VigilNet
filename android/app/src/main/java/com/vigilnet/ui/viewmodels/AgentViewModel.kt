package com.vigilnet.ui.viewmodels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.vigilnet.ffi.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.util.*

/**
 * ViewModel for agent management
 */
class AgentViewModel : ViewModel() {
    
    private val _agents = MutableStateFlow<List<AgentInfo>>(emptyList())
    val agents: StateFlow<List<AgentInfo>> = _agents.asStateFlow()
    
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()
    
    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()
    
    private val _isInitialized = MutableStateFlow(false)
    val isInitialized: StateFlow<Boolean> = _isInitialized.asStateFlow()
    
    init {
        // Load mock agents for demonstration
        loadMockAgents()
    }
    
    private fun loadMockAgents() {
        _agents.value = listOf(
            AgentInfo(
                id = UUID.randomUUID().toString(),
                name = "Mesh Agent",
                type = AgentType.MESH,
                status = AgentStatus.RUNNING,
                peerCount = 5,
                lastActive = System.currentTimeMillis()
            ),
            AgentInfo(
                id = UUID.randomUUID().toString(),
                name = "Circle Agent",
                type = AgentType.CIRCLE,
                status = AgentStatus.RUNNING,
                peerCount = 3,
                lastActive = System.currentTimeMillis() - 60000
            )
        )
    }
    
    fun initializeAgents(enableMesh: Boolean, enableCircles: Boolean, enableResearch: Boolean) {
        viewModelScope.launch {
            _isLoading.value = true
            _errorMessage.value = null
            
            try {
                val result = RustBridge.initAgents(enableMesh, enableCircles, enableResearch)
                if (result != 0) {
                    _errorMessage.value = "Failed to initialize agents"
                } else {
                    _isInitialized.value = true
                }
            } catch (e: Exception) {
                _errorMessage.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun startAgents() {
        viewModelScope.launch {
            _isLoading.value = true
            _errorMessage.value = null
            
            try {
                val result = RustBridge.startAgents()
                if (result != 0) {
                    _errorMessage.value = "Failed to start agents"
                } else {
                    updateAgentStatus(AgentStatus.RUNNING)
                }
            } catch (e: Exception) {
                _errorMessage.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun stopAgents() {
        viewModelScope.launch {
            _isLoading.value = true
            
            try {
                val result = RustBridge.stopAgents()
                if (result != 0) {
                    _errorMessage.value = "Failed to stop agents"
                } else {
                    updateAgentStatus(AgentStatus.STOPPED)
                }
            } catch (e: Exception) {
                _errorMessage.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun startMeshAgent() {
        viewModelScope.launch {
            _isLoading.value = true
            
            try {
                val result = RustBridge.startMesh()
                if (result != 0) {
                    _errorMessage.value = "Failed to start mesh agent"
                } else {
                    updateAgentTypeStatus(AgentType.MESH, AgentStatus.RUNNING)
                }
            } catch (e: Exception) {
                _errorMessage.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun stopMeshAgent() {
        viewModelScope.launch {
            _isLoading.value = true
            
            try {
                val result = RustBridge.stopMesh()
                if (result != 0) {
                    _errorMessage.value = "Failed to stop mesh agent"
                } else {
                    updateAgentTypeStatus(AgentType.MESH, AgentStatus.STOPPED)
                }
            } catch (e: Exception) {
                _errorMessage.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
    
    fun sendMessageToAgent(agentId: String, message: String) {
        viewModelScope.launch {
            // In a real implementation, this would call RustBridge
            // For now, we'll just simulate success
            _errorMessage.value = null
        }
    }
    
    fun createAgent(name: String, type: AgentType) {
        val newAgent = AgentInfo(
            id = UUID.randomUUID().toString(),
            name = name,
            type = type,
            status = AgentStatus.STARTING,
            peerCount = 0,
            lastActive = System.currentTimeMillis()
        )
        
        _agents.value = _agents.value + newAgent
        
        // Start the agent after creation
        viewModelScope.launch {
            // Simulate startup delay
            kotlinx.coroutines.delay(1000)
            updateAgentStatusById(newAgent.id, AgentStatus.RUNNING)
        }
    }
    
    fun removeAgent(agentId: String) {
        _agents.value = _agents.value.filter { it.id != agentId }
    }
    
    private fun updateAgentStatus(status: AgentStatus) {
        _agents.value = _agents.value.map { it.copy(status = status) }
    }
    
    private fun updateAgentTypeStatus(type: AgentType, status: AgentStatus) {
        _agents.value = _agents.value.map { agent ->
            if (agent.type == type) {
                agent.copy(status = status)
            } else {
                agent
            }
        }
    }
    
    private fun updateAgentStatusById(agentId: String, status: AgentStatus) {
        _agents.value = _agents.value.map { agent ->
            if (agent.id == agentId) {
                agent.copy(status = status)
            } else {
                agent
            }
        }
    }
    
    fun clearError() {
        _errorMessage.value = null
    }
    
    fun getAgentStatusColor(status: AgentStatus): String {
        return when (status) {
            AgentStatus.RUNNING -> "#22C55E"
            AgentStatus.STARTING -> "#F59E0B"
            AgentStatus.STOPPED -> "#64748B"
            AgentStatus.ERROR -> "#EF4444"
        }
    }
}
