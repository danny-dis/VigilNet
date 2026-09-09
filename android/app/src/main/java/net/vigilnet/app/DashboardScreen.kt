package net.vigilnet.app

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun DashboardScreen(
    viewModel: VigilNetViewModel, 
    onStartRequested: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onNavigateToCircles: () -> Unit
) {
    val state by viewModel.uiState
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VigilNetTheme.DeepObsidian)
            .padding(24.dp)
            .statusBarsPadding()
    ) {
        // Top Bar
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "VigilNet",
                    style = MaterialTheme.typography.displaySmall,
                    color = Color.White,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = if (state.isVpnRunning) "PROTECTED" else "UNPROTECTED",
                    color = if (state.isVpnRunning) VigilNetTheme.Safe else VigilNetTheme.Warning,
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.SemiBold
                )
            }
            
            // Settings / Profile Button
            Row {
                IconButton(onClick = onNavigateToCircles) {
                    Text(text = "👥", fontSize = 20.sp)
                }
                IconButton(onClick = onNavigateToSettings) {
                    Text(text = "⚙️", fontSize = 20.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(48.dp))

        // Main VPN Toggle
        VpnToggleButton(
            isRunning = state.isVpnRunning,
            onClick = {
                viewModel.toggleVpn { if (it) onStartRequested() }
            }
        )

        Spacer(modifier = Modifier.height(64.dp))

        // Backends Grid
        Text(
            text = "Network Backends",
            color = Color.White.copy(alpha = 0.7f),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold
        )
        
        Spacer(modifier = Modifier.height(16.dp))

        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            horizontalArrangement = Arrangement.spacedBy(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            modifier = Modifier.fillMaxWidth()
        ) {
            items(state.backends) { backend ->
                BackendCard(
                    backend = backend,
                    onClick = { viewModel.toggleBackend(backend.type) }
                )
            }
        }
    }
}

@Composable
fun VpnToggleButton(isRunning: Boolean, onClick: () -> Unit) {
    val infiniteTransition = androidx.compose.animation.core.rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (isRunning) 1.15f else 1f,
        animationSpec = androidx.compose.animation.core.infiniteRepeatable(
            animation = androidx.compose.animation.core.tween(1500, easing = androidx.compose.animation.core.FastOutSlowInEasing),
            repeatMode = androidx.compose.animation.core.RepeatMode.Reverse
        ),
        label = "scale"
    )

    val color by animateColorAsState(
        if (isRunning) VigilNetTheme.NeonGreen else VigilNetTheme.AmberWarning, 
        label = "color"
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(240.dp),
        contentAlignment = Alignment.Center
    ) {
        // Outer Glow Layers (Pulsing)
        if (isRunning) {
            Box(
                modifier = Modifier
                    .size(180.dp * pulseScale)
                    .background(color.copy(alpha = 0.15f), CircleShape)
            )
            Box(
                modifier = Modifier
                    .size(220.dp * pulseScale)
                    .background(color.copy(alpha = 0.05f), CircleShape)
            )
        }

        // The Main Button
        Surface(
            modifier = Modifier
                .size(150.dp)
                .clickable { onClick() }
                .shadow(
                    elevation = if (isRunning) 30.dp else 4.dp,
                    shape = CircleShape,
                    spotColor = color,
                    ambientColor = color
                ),
            shape = CircleShape,
            color = VigilNetTheme.SurfaceObsidian,
            border = androidx.compose.foundation.BorderStroke(2.dp, color.copy(alpha = if (isRunning) 1f else 0.4f))
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text(
                    text = if (isRunning) "🛡️" else "🔓",
                    fontSize = 44.sp
                )
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = if (isRunning) "PROTECTED" else "READY",
                    color = color,
                    fontWeight = FontWeight.ExtraBold,
                    style = MaterialTheme.typography.labelLarge
                )
            }
        }
    }
}

@Composable
fun BackendCard(backend: BackendState, onClick: () -> Unit) {
    val color = if (backend.isConnected) VigilNetTheme.NeonGreen 
                else if (backend.isEnabled) VigilNetTheme.ElectricCyan 
                else Color.White.copy(alpha = 0.2f)

    Surface(
        color = VigilNetTheme.GlassWhite,
        shape = RoundedCornerShape(24.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, VigilNetTheme.GlassStroke),
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(24.dp))
            .clickable { onClick() }
    ) {
        Column(
            modifier = Modifier.padding(20.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(VigilNetTheme.SurfaceObsidian, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = backend.type.icon,
                        fontSize = 24.sp
                    )
                }
                
                // Status indicator
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .shadow(if (backend.isEnabled) 8.dp else 0.dp, CircleShape, color, color)
                        .background(color, CircleShape)
                )
            }
            
            Spacer(modifier = Modifier.height(20.dp))
            
            Text(
                text = backend.type.displayName,
                color = Color.White,
                fontWeight = FontWeight.Black,
                style = MaterialTheme.typography.titleMedium
            )
            
            Text(
                text = if (backend.isConnected) "ESTABLISHED" else if (backend.isEnabled) "BOOTSTRAPPING" else "DISABLED",
                color = color.copy(alpha = 0.7f),
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold
            )
        }
    }
}
