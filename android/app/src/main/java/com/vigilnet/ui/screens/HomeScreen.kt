package com.vigilnet.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
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
import com.vigilnet.ffi.*
import com.vigilnet.ui.theme.*
import com.vigilnet.ui.viewmodels.ConnectionViewModel
import java.text.DecimalFormat

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    viewModel: ConnectionViewModel = viewModel(),
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit
) {
    val connectionState by viewModel.connectionState.collectAsState()
    val selectedBackend by viewModel.selectedBackend.collectAsState()
    val tunnelStats by viewModel.tunnelStats.collectAsState()
    val networkStatuses by viewModel.networkStatuses.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    val routingChain by viewModel.routingChain.collectAsState()
    
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
                title = { Text("VigilNet") },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Connection Toggle Card
            ConnectionToggleCard(
                connectionState = connectionState,
                selectedBackend = selectedBackend,
                onToggle = {
                    if (connectionState == ConnectionState.CONNECTED) {
                        viewModel.disconnect()
                        onStopVpn()
                    } else {
                        viewModel.connect()
                        onStartVpn()
                    }
                },
                isLoading = isLoading
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Stats Card
            StatsCard(
                stats = tunnelStats,
                isConnected = connectionState == ConnectionState.CONNECTED
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Network Backend Selection
            NetworkBackendSelection(
                selectedBackend = selectedBackend,
                networkStatuses = networkStatuses,
                onBackendSelected = { viewModel.selectBackend(it) }
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Multi-hop Routing Chain
            RoutingChainCard(
                routingChain = routingChain,
                onAddBackend = { viewModel.addToRoutingChain(it) },
                onRemoveBackend = { viewModel.removeFromRoutingChain(it) },
                onClear = { viewModel.clearRoutingChain() }
            )
        }
    }
}

@Composable
fun ConnectionToggleCard(
    connectionState: ConnectionState,
    selectedBackend: Int,
    onToggle: () -> Unit,
    isLoading: Boolean
) {
    val (statusColor, statusText, icon) = when (connectionState) {
        ConnectionState.CONNECTED -> Triple(StatusConnected, "Connected", Icons.Default.CheckCircle)
        ConnectionState.CONNECTING -> Triple(StatusConnecting, "Connecting...", Icons.Default.Sync)
        ConnectionState.DISCONNECTED -> Triple(StatusDisconnected, "Disconnected", Icons.Default.PowerOff)
        ConnectionState.ERROR -> Triple(StatusError, "Error", Icons.Default.Error)
    }
    
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
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Status Indicator
            Box(
                modifier = Modifier
                    .size(120.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = 0.2f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = icon,
                    contentDescription = statusText,
                    modifier = Modifier.size(56.dp),
                    tint = statusColor
                )
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Text(
                text = statusText,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = statusColor
            )
            
            Spacer(modifier = Modifier.height(4.dp))
            
            Text(
                text = "${NetworkBackend.getDisplayName(selectedBackend)}",
                style = MaterialTheme.typography.bodyLarge,
                color = TextSecondaryDark
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Toggle Button
            Button(
                onClick = onToggle,
                enabled = !isLoading,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (connectionState == ConnectionState.CONNECTED) 
                        StatusDisconnected else VigilNetPrimary
                ),
                shape = RoundedCornerShape(12.dp)
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = Color.White
                    )
                } else {
                    Text(
                        text = if (connectionState == ConnectionState.CONNECTED) 
                            "Disconnect" else "Connect",
                        style = MaterialTheme.typography.titleLarge
                    )
                }
            }
        }
    }
}

@Composable
fun StatsCard(
    stats: TunnelStats,
    isConnected: Boolean
) {
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
                text = "Connection Stats",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                StatItem(
                    icon = Icons.Default.ArrowUpward,
                    label = "Sent",
                    value = formatBytes(stats.bytesSent),
                    color = VigilNetPrimary
                )
                StatItem(
                    icon = Icons.Default.ArrowDownward,
                    label = "Received",
                    value = formatBytes(stats.bytesReceived),
                    color = StatusConnected
                )
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                StatItem(
                    icon = Icons.Default.Send,
                    label = "Packets Out",
                    value = stats.packetsSent.toString(),
                    color = VigilNetSecondary
                )
                StatItem(
                    icon = Icons.Default.Download,
                    label = "Packets In",
                    value = stats.packetsReceived.toString(),
                    color = VigilNetTertiary
                )
            }
        }
    }
}

@Composable
fun StatItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    value: String,
    color: Color
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = color,
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = TextPrimaryDark
        )
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = TextTertiaryDark
        )
    }
}

@Composable
fun NetworkBackendSelection(
    selectedBackend: Int,
    networkStatuses: List<NetworkStatus>,
    onBackendSelected: (Int) -> Unit
) {
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
                text = "Network Backend",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Show available backends
            val availableBackends = listOf(
                NetworkBackend.CLEARNET,
                NetworkBackend.TOR,
                NetworkBackend.I2P,
                NetworkBackend.WIREGUARD,
                NetworkBackend.NYM
            )
            
            availableBackends.chunked(2).forEach { rowBackends ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    rowBackends.forEach { backendId ->
                        val isSelected = selectedBackend == backendId
                        val status = networkStatuses.find { it.backendId == backendId }
                        val isEnabled = status?.enabled ?: false
                        
                        BackendChip(
                            backendId = backendId,
                            isSelected = isSelected,
                            isEnabled = isEnabled,
                            onClick = { onBackendSelected(backendId) },
                            modifier = Modifier.weight(1f)
                        )
                    }
                    
                    // Fill remaining space if odd number
                    if (rowBackends.size < 2) {
                        Spacer(modifier = Modifier.weight(1f))
                    }
                }
                
                Spacer(modifier = Modifier.height(8.dp))
            }
        }
    }
}

@Composable
fun BackendChip(
    backendId: Int,
    isSelected: Boolean,
    isEnabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val color = when (backendId) {
        NetworkBackend.TOR -> BackendTor
        NetworkBackend.I2P -> BackendI2P
        NetworkBackend.WIREGUARD -> BackendWireGuard
        NetworkBackend.NYM -> BackendNym
        else -> BackendClearnet
    }
    
    val anonymityLevel = NetworkBackend.getAnonymityLevel(backendId)
    
    FilterChip(
        selected = isSelected,
        onClick = onClick,
        label = {
            Column {
                Text(
                    text = NetworkBackend.getDisplayName(backendId).substringBefore(" "),
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "Privacy: $anonymityLevel/10",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextTertiaryDark
                )
            }
        },
        modifier = modifier,
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = color.copy(alpha = 0.2f),
            selectedLabelColor = color
        ),
        leadingIcon = if (isEnabled) {
            {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(StatusConnected)
                )
            }
        } else null
    )
}

@Composable
fun RoutingChainCard(
    routingChain: List<Int>,
    onAddBackend: (Int) -> Unit,
    onRemoveBackend: (Int) -> Unit,
    onClear: () -> Unit
) {
    var showAddDialog by remember { mutableStateOf(false) }
    
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
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Multi-hop Routing",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                
                if (routingChain.isNotEmpty()) {
                    TextButton(onClick = onClear) {
                        Text("Clear")
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            if (routingChain.isEmpty()) {
                Text(
                    text = "No multi-hop routing configured. Tap + to add backends.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextTertiaryDark
                )
            } else {
                Column {
                    routingChain.forEachIndexed { index, backendId ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "${index + 1}.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = VigilNetPrimary,
                                modifier = Modifier.width(24.dp)
                            )
                            
                            Text(
                                text = NetworkBackend.getDisplayName(backendId),
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.weight(1f)
                            )
                            
                            IconButton(
                                onClick = { onRemoveBackend(backendId) }
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Close,
                                    contentDescription = "Remove",
                                    tint = StatusError
                                )
                            }
                        }
                        
                        if (index < routingChain.size - 1) {
                            Icon(
                                imageVector = Icons.Default.ArrowDownward,
                                contentDescription = null,
                                modifier = Modifier.padding(start = 8.dp),
                                tint = TextTertiaryDark
                            )
                        }
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            OutlinedButton(
                onClick = { showAddDialog = true },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Add, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Add Backend to Chain")
            }
        }
    }
    
    if (showAddDialog) {
        AlertDialog(
            onDismissRequest = { showAddDialog = false },
            title = { Text("Add to Routing Chain") },
            text = {
                Column {
                    listOf(
                        NetworkBackend.TOR,
                        NetworkBackend.I2P,
                        NetworkBackend.WIREGUARD,
                        NetworkBackend.NYM
                    ).forEach { backendId ->
                        TextButton(
                            onClick = {
                                onAddBackend(backendId)
                                showAddDialog = false
                            }
                        ) {
                            Text(NetworkBackend.getDisplayName(backendId))
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = { showAddDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }
}

private fun formatBytes(bytes: Long): String {
    val df = DecimalFormat("0.00")
    return when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${df.format(bytes / 1024.0)} KB"
        bytes < 1024 * 1024 * 1024 -> "${df.format(bytes / (1024.0 * 1024.0))} MB"
        else -> "${df.format(bytes / (1024.0 * 1024.0 * 1024.0))} GB"
    }
}
