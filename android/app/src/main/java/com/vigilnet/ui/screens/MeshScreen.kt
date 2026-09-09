package com.vigilnet.ui.screens

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
import com.vigilnet.ui.theme.*
import com.vigilnet.ui.viewmodels.AgentViewModel
import kotlin.math.cos
import kotlin.math.sin

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MeshScreen(
    viewModel: AgentViewModel = viewModel()
) {
    val agents by viewModel.agents.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    
    // Get mesh agent status
    val meshAgent = agents.find { it.type == com.vigilnet.ffi.AgentType.MESH }
    val isMeshRunning = meshAgent?.status == com.vigilnet.ffi.AgentStatus.RUNNING
    val peerCount = meshAgent?.peerCount ?: 0
    
    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Mesh Network") },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            // Mesh Status Card
            MeshStatusCard(
                isRunning = isMeshRunning,
                peerCount = peerCount,
                onStart = { viewModel.startMeshAgent() },
                onStop = { viewModel.stopMeshAgent() },
                isLoading = isLoading
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Transport Indicators
            TransportIndicatorsCard()
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Connection Graph Visualization
            ConnectionGraphCard(peerCount = peerCount)
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Network Stats
            MeshStatsCard()
        }
    }
}

@Composable
fun MeshStatusCard(
    isRunning: Boolean,
    peerCount: Int,
    onStart: () -> Unit,
    onStop: () -> Unit,
    isLoading: Boolean
) {
    val statusColor = if (isRunning) StatusConnected else StatusDisconnected
    val statusText = if (isRunning) "Active" else "Inactive"
    
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
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Status Icon
            Box(
                modifier = Modifier
                    .size(80.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = 0.2f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = if (isRunning) Icons.Default.Hub else Icons.Default.Hub,
                    contentDescription = statusText,
                    modifier = Modifier.size(40.dp),
                    tint = statusColor
                )
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Text(
                text = "Mesh Network",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.height(4.dp))
            
            Text(
                text = statusText,
                style = MaterialTheme.typography.titleMedium,
                color = statusColor
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = "$peerCount peers connected",
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondaryDark
            )
            
            Spacer(modifier = Modifier.height(20.dp))
            
            // Control Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                if (!isRunning) {
                    Button(
                        onClick = onStart,
                        enabled = !isLoading,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        if (isLoading) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = Color.White
                            )
                        } else {
                            Icon(Icons.Default.PlayArrow, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Start Mesh")
                        }
                    }
                } else {
                    Button(
                        onClick = onStop,
                        enabled = !isLoading,
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = StatusDisconnected
                        ),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        if (isLoading) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                color = Color.White
                            )
                        } else {
                            Icon(Icons.Default.Stop, contentDescription = null)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Stop Mesh")
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun TransportIndicatorsCard() {
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
                text = "Transport Protocols",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // BLE
            TransportIndicator(
                label = "Bluetooth Low Energy",
                status = "Available",
                statusColor = StatusConnected,
                icon = Icons.Default.Bluetooth
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // WiFi Direct
            TransportIndicator(
                label = "WiFi Direct",
                status = "Available",
                statusColor = StatusConnected,
                icon = Icons.Default.Wifi
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // LoRa
            TransportIndicator(
                label = "LoRa",
                status = "Hardware not detected",
                statusColor = StatusDisconnected,
                icon = Icons.Default.SettingsInputAntenna
            )
        }
    }
}

@Composable
fun TransportIndicator(
    label: String,
    status: String,
    statusColor: Color,
    icon: androidx.compose.ui.graphics.vector.ImageVector
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(SurfaceVariantDark),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = VigilNetPrimary,
                modifier = Modifier.size(24.dp)
            )
        }
        
        Spacer(modifier = Modifier.width(16.dp))
        
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium
            )
            Text(
                text = status,
                style = MaterialTheme.typography.bodySmall,
                color = statusColor
            )
        }
    }
}

@Composable
fun ConnectionGraphCard(peerCount: Int) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .height(250.dp),
        colors = CardDefaults.cardColors(
            containerColor = SurfaceDark
        ),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(20.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Network Topology",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                
                Text(
                    text = "$peerCount nodes",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondaryDark
                )
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Visual representation of mesh network
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                if (peerCount == 0) {
                    Text(
                        text = "No active connections",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextTertiaryDark
                    )
                } else {
                    MeshGraphVisualization(peerCount = peerCount)
                }
            }
        }
    }
}

@Composable
fun MeshGraphVisualization(peerCount: Int) {
    // Simple visualization of mesh nodes
    Box(modifier = Modifier.fillMaxSize()) {
        // Center node (this device)
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(VigilNetPrimary)
                .align(Alignment.Center),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Smartphone,
                contentDescription = "You",
                tint = Color.White,
                modifier = Modifier.size(20.dp)
            )
        }
        
        // Peer nodes arranged in a circle
        val radius = 70.dp
        val angleStep = 360f / maxOf(peerCount, 1)
        
        repeat(peerCount) { index ->
            val angle = Math.toRadians((angleStep * index - 90).toDouble())
            val x = (cos(angle) * radius.value).dp
            val y = (sin(angle) * radius.value).dp
            
            Box(
                modifier = Modifier
                    .size(32.dp)
                    .offset(x, y)
                    .clip(CircleShape)
                    .background(MeshWiFi)
                    .align(Alignment.Center),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.DeviceHub,
                    contentDescription = "Peer",
                    tint = Color.White,
                    modifier = Modifier.size(16.dp)
                )
            }
        }
    }
}

@Composable
fun MeshStatsCard() {
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
                text = "Mesh Statistics",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                MeshStatItem(
                    label = "Messages",
                    value = "1,247",
                    icon = Icons.Default.Message
                )
                MeshStatItem(
                    label = "Data Relayed",
                    value = "45.2 MB",
                    icon = Icons.Default.SwapHoriz
                )
                MeshStatItem(
                    label = "Uptime",
                    value = "2h 34m",
                    icon = Icons.Default.Schedule
                )
            }
        }
    }
}

@Composable
fun MeshStatItem(
    label: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = VigilNetSecondary,
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
