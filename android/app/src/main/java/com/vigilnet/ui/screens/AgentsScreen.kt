package com.vigilnet.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vigilnet.ffi.AgentInfo
import com.vigilnet.ffi.AgentStatus
import com.vigilnet.ffi.AgentType
import com.vigilnet.ui.theme.*
import com.vigilnet.ui.viewmodels.AgentViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AgentsScreen(
    viewModel: AgentViewModel = viewModel()
) {
    val agents by viewModel.agents.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    val isInitialized by viewModel.isInitialized.collectAsState()
    
    var showCreateDialog by remember { mutableStateOf(false) }
    var selectedAgent by remember { mutableStateOf<AgentInfo?>(null) }
    var showAgentDetails by remember { mutableStateOf(false) }
    
    val snackbarHostState = remember { SnackbarHostState() }
    
    LaunchedEffect(errorMessage) {
        errorMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearError()
        }
    }
    
    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Agents") },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                ),
                actions = {
                    if (isInitialized) {
                        IconButton(onClick = { viewModel.startAgents() }) {
                            Icon(Icons.Default.PlayArrow, contentDescription = "Start All")
                        }
                        IconButton(onClick = { viewModel.stopAgents() }) {
                            Icon(Icons.Default.Stop, contentDescription = "Stop All")
                        }
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showCreateDialog = true },
                containerColor = VigilNetPrimary
            ) {
                Icon(Icons.Default.Add, contentDescription = "Create Agent")
            }
        },
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            if (!isInitialized) {
                InitializeCard(
                    onInitialize = { mesh, circles, research ->
                        viewModel.initializeAgents(mesh, circles, research)
                    },
                    isLoading = isLoading
                )
            } else {
                if (agents.isEmpty()) {
                    EmptyAgentsState()
                } else {
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        items(agents) { agent ->
                            AgentCard(
                                agent = agent,
                                onClick = {
                                    selectedAgent = agent
                                    showAgentDetails = true
                                }
                            )
                        }
                    }
                }
            }
        }
    }
    
    // Create Agent Dialog
    if (showCreateDialog) {
        CreateAgentDialog(
            onDismiss = { showCreateDialog = false },
            onCreate = { name, type ->
                viewModel.createAgent(name, type)
                showCreateDialog = false
            }
        )
    }
    
    // Agent Details Dialog
    if (showAgentDetails && selectedAgent != null) {
        AgentDetailsDialog(
            agent = selectedAgent!!,
            onDismiss = { 
                showAgentDetails = false
                selectedAgent = null
            },
            onStart = {
                when (selectedAgent!!.type) {
                    AgentType.MESH -> viewModel.startMeshAgent()
                    else -> {}
                }
            },
            onStop = {
                when (selectedAgent!!.type) {
                    AgentType.MESH -> viewModel.stopMeshAgent()
                    else -> {}
                }
            },
            onSendMessage = { message ->
                viewModel.sendMessageToAgent(selectedAgent!!.id, message)
            }
        )
    }
}

@Composable
fun InitializeCard(
    onInitialize: (Boolean, Boolean, Boolean) -> Unit,
    isLoading: Boolean
) {
    var enableMesh by remember { mutableStateOf(true) }
    var enableCircles by remember { mutableStateOf(true) }
    var enableResearch by remember { mutableStateOf(false) }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = SurfaceDark
        ),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {
            Text(
                text = "Initialize Agents",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = "Select which agents to enable",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondaryDark
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Agent type toggles
            AgentToggle(
                label = "Mesh Agent",
                description = "P2P mesh networking fallback",
                checked = enableMesh,
                onCheckedChange = { enableMesh = it }
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            AgentToggle(
                label = "Circle Agent",
                description = "Trust circles and invites",
                checked = enableCircles,
                onCheckedChange = { enableCircles = it }
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            AgentToggle(
                label = "Research Agent",
                description = "Network research and analytics",
                checked = enableResearch,
                onCheckedChange = { enableResearch = it }
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            Button(
                onClick = { onInitialize(enableMesh, enableCircles, enableResearch) },
                enabled = !isLoading,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = Color.White
                    )
                } else {
                    Text("Initialize")
                }
            }
        }
    }
}

@Composable
fun AgentToggle(
    label: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = TextTertiaryDark
            )
        }
        
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange
        )
    }
}

@Composable
fun EmptyAgentsState() {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.SmartToy,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = TextTertiaryDark
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            text = "No Agents Running",
            style = MaterialTheme.typography.titleLarge,
            color = TextSecondaryDark
        )
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Text(
            text = "Tap + to create a new agent",
            style = MaterialTheme.typography.bodyMedium,
            color = TextTertiaryDark
        )
    }
}

@Composable
fun AgentCard(
    agent: AgentInfo,
    onClick: () -> Unit
) {
    val statusColor = when (agent.status) {
        AgentStatus.RUNNING -> StatusConnected
        AgentStatus.STARTING -> StatusConnecting
        AgentStatus.STOPPED -> TextTertiaryDark
        AgentStatus.ERROR -> StatusError
    }
    
    val typeIcon = when (agent.type) {
        AgentType.MESH -> Icons.Default.Hub
        AgentType.CIRCLE -> Icons.Default.Groups
        AgentType.RESEARCH -> Icons.Default.Science
    }
    
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = SurfaceDark
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Status indicator
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .clip(CircleShape)
                    .background(statusColor)
            )
            
            Spacer(modifier = Modifier.width(16.dp))
            
            // Agent type icon
            Icon(
                imageVector = typeIcon,
                contentDescription = null,
                tint = VigilNetPrimary,
                modifier = Modifier.size(32.dp)
            )
            
            Spacer(modifier = Modifier.width(16.dp))
            
            // Agent info
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = agent.name,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "${agent.type.name.lowercase().replaceFirstChar { it.uppercase() }} • ${agent.status.name.lowercase().replaceFirstChar { it.uppercase() }}",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextTertiaryDark
                )
            }
            
            // Peer count
            if (agent.peerCount > 0) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.People,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = TextSecondaryDark
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = agent.peerCount.toString(),
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondaryDark
                    )
                }
            }
            
            Spacer(modifier = Modifier.width(8.dp))
            
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = "Details",
                tint = TextTertiaryDark
            )
        }
    }
}

@Composable
fun CreateAgentDialog(
    onDismiss: () -> Unit,
    onCreate: (String, AgentType) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf(AgentType.MESH) }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Create New Agent") },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Agent Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Text(
                    text = "Agent Type",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                AgentType.values().forEach { type ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = selectedType == type,
                            onClick = { selectedType = type }
                        )
                        Text(
                            text = type.name.lowercase().replaceFirstChar { it.uppercase() },
                            modifier = Modifier.padding(start = 8.dp)
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = { onCreate(name, selectedType) },
                enabled = name.isNotBlank()
            ) {
                Text("Create")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel")
            }
        }
    )
}

@Composable
fun AgentDetailsDialog(
    agent: AgentInfo,
    onDismiss: () -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit,
    onSendMessage: (String) -> Unit
) {
    var message by remember { mutableStateOf("") }
    var showSendMessage by remember { mutableStateOf(false) }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(agent.name) },
        text = {
            Column {
                // Status
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val statusColor = when (agent.status) {
                        AgentStatus.RUNNING -> StatusConnected
                        AgentStatus.STARTING -> StatusConnecting
                        AgentStatus.STOPPED -> TextTertiaryDark
                        AgentStatus.ERROR -> StatusError
                    }
                    
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .clip(CircleShape)
                            .background(statusColor)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Text(
                        text = "Status: ${agent.status.name}",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    text = "Type: ${agent.type.name}",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                Text(
                    text = "Peers: ${agent.peerCount}",
                    style = MaterialTheme.typography.bodyMedium
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Actions
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (agent.status == AgentStatus.STOPPED) {
                        Button(
                            onClick = onStart,
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Start")
                        }
                    } else {
                        Button(
                            onClick = onStop,
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = StatusDisconnected
                            )
                        ) {
                            Text("Stop")
                        }
                    }
                    
                    OutlinedButton(
                        onClick = { showSendMessage = true },
                        modifier = Modifier.weight(1f)
                    ) {
                        Text("Message")
                    }
                }
                
                // Send message UI
                if (showSendMessage) {
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    OutlinedTextField(
                        value = message,
                        onValueChange = { message = it },
                        label = { Text("Message") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    Button(
                        onClick = {
                            onSendMessage(message)
                            message = ""
                            showSendMessage = false
                        },
                        enabled = message.isNotBlank(),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Send")
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Close")
            }
        }
    )
}
