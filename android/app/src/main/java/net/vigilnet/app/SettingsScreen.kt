package net.vigilnet.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun SettingsScreen(viewModel: VigilNetViewModel, onNavigateBack: () -> Unit) {
    val state by viewModel.uiState
    var newBridgeText by remember { mutableStateOf("") }
    var newAppText by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(VigilNetTheme.DeepObsidian)
            .statusBarsPadding()
    ) {
        // Top Bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = onNavigateBack,
                modifier = Modifier.background(VigilNetTheme.SurfaceObsidian, CircleShape)
            ) {
                Text(text = "⬅️", fontSize = 18.sp)
            }
            Spacer(modifier = Modifier.width(16.dp))
            Text(
                text = "Configurations",
                style = MaterialTheme.typography.headlineSmall,
                color = Color.White,
                fontWeight = FontWeight.Black
            )
        }
        
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            // Tor Configuration Section
            item {
                SectionHeader("Tor Network")
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedTextField(
                    value = newBridgeText,
                    onValueChange = { newBridgeText = it },
                    placeholder = { Text("obfs4 1.2.3.4:1234 ...", color = Color.White.copy(alpha = 0.3f)) },
                    label = { Text("Add Bridge Line") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        focusedContainerColor = VigilNetTheme.SurfaceObsidian,
                        unfocusedContainerColor = VigilNetTheme.SurfaceObsidian,
                        focusedBorderColor = VigilNetTheme.ElectricCyan,
                        unfocusedBorderColor = VigilNetTheme.GlassStroke,
                        focusedLabelColor = VigilNetTheme.ElectricCyan,
                        unfocusedLabelColor = Color.White.copy(alpha = 0.5f)
                    )
                )
                
                Button(
                    onClick = {
                        if (newBridgeText.isNotBlank()) {
                            viewModel.updateTorBridges(state.torBridges + newBridgeText)
                            newBridgeText = ""
                        }
                    },
                    modifier = Modifier
                        .padding(top = 12.dp)
                        .fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = VigilNetTheme.ElectricCyan)
                ) {
                    Text("Add Relay Bridge", color = Color.Black, fontWeight = FontWeight.Bold)
                }
            }

            items(state.torBridges) { bridge ->
                SettingsItem(text = bridge, onRemove = {
                    viewModel.updateTorBridges(state.torBridges.filter { it != bridge })
                })
            }

            // Split Tunneling Section
            item {
                SectionHeader("Privacy Rules")
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedTextField(
                    value = newAppText,
                    onValueChange = { newAppText = it },
                    placeholder = { Text("com.google.android.youtube", color = Color.White.copy(alpha = 0.3f)) },
                    label = { Text("Exclude App (Package)") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.White,
                        focusedContainerColor = VigilNetTheme.SurfaceObsidian,
                        unfocusedContainerColor = VigilNetTheme.SurfaceObsidian,
                        focusedBorderColor = VigilNetTheme.NeonGreen,
                        unfocusedBorderColor = VigilNetTheme.GlassStroke,
                        focusedLabelColor = VigilNetTheme.NeonGreen,
                        unfocusedLabelColor = Color.White.copy(alpha = 0.5f)
                    )
                )
                
                Button(
                    onClick = {
                        if (newAppText.isNotBlank()) {
                            viewModel.addExcludedApp(newAppText)
                            newAppText = ""
                        }
                    },
                    modifier = Modifier
                        .padding(top = 12.dp)
                        .fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = VigilNetTheme.NeonGreen)
                ) {
                    Text("Whitelist App", color = Color.Black, fontWeight = FontWeight.Bold)
                }
            }

            items(state.excludedApps.toList()) { pkg ->
                SettingsItem(text = pkg, onRemove = {
                    viewModel.removeExcludedApp(pkg)
                })
            }
            
            // Multi-Hop Routing Section
            item {
                SectionHeader("Advanced Routing")
                Spacer(modifier = Modifier.height(8.dp))
                Surface(
                    color = VigilNetTheme.GlassWhite,
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, VigilNetTheme.GlassStroke),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = if (state.activeChain.isEmpty()) "Default: Direct to Backend" 
                               else "Chain: ${state.activeChain.joinToString(" ➔ ") { it.displayName }}",
                        color = Color.White.copy(alpha = 0.6f),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }

            item {
                Spacer(modifier = Modifier.height(40.dp))
            }
        }
    }
}

@Composable
fun SectionHeader(title: String) {
    Text(
        text = title.uppercase(),
        style = MaterialTheme.typography.labelLarge,
        color = VigilNetTheme.ElectricCyan,
        fontWeight = FontWeight.Black,
        letterSpacing = 2.sp
    )
}

@Composable
fun SettingsItem(text: String, onRemove: () -> Unit) {
    Surface(
        color = VigilNetTheme.SurfaceObsidian,
        shape = RoundedCornerShape(16.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, VigilNetTheme.GlassStroke),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = text,
                color = Color.White,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
            )
            IconButton(
                onClick = onRemove,
                modifier = Modifier.size(24.dp)
            ) {
                Text(text = "❌", fontSize = 12.sp)
            }
        }
    }
}
