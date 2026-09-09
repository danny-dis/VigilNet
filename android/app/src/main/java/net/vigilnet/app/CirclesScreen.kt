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
fun CirclesScreen(viewModel: VigilNetViewModel, onNavigateBack: () -> Unit) {
    val state by viewModel.uiState
    var circleName by remember { mutableStateOf("") }
    var inviteJson by remember { mutableStateOf("") }

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
                text = "Agent Circles",
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
            // Create Circle Section
            item {
                SectionHeader("Establish New Circle")
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedTextField(
                    value = circleName,
                    onValueChange = { circleName = it },
                    placeholder = { Text("e.g. Tactical Overlay 1", color = Color.White.copy(alpha = 0.3f)) },
                    label = { Text("Circle Identity") },
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
                        if (circleName.isNotBlank()) {
                            viewModel.createCircle(circleName, "/data/user/0/net.vigilnet.app/files/")
                            circleName = ""
                        }
                    },
                    modifier = Modifier
                        .padding(top = 12.dp)
                        .fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = VigilNetTheme.ElectricCyan)
                ) {
                    Text("Initialize Circle", color = Color.Black, fontWeight = FontWeight.Bold)
                }
            }

            // Join Circle Section
            item {
                SectionHeader("Secure Join")
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedTextField(
                    value = inviteJson,
                    onValueChange = { inviteJson = it },
                    placeholder = { Text("Paste JSON invite here...", color = Color.White.copy(alpha = 0.3f)) },
                    label = { Text("Invite Payload") },
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
                        if (inviteJson.isNotBlank()) {
                            viewModel.joinCircle(inviteJson, "/data/user/0/net.vigilnet.app/files/")
                            inviteJson = ""
                        }
                    },
                    modifier = Modifier
                        .padding(top = 12.dp)
                        .fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = VigilNetTheme.NeonGreen)
                ) {
                    Text("Join Mesh Circle", color = Color.Black, fontWeight = FontWeight.Bold)
                }
            }

            // Active Circles List
            item {
                SectionHeader("Active Circles")
                if (state.circles.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 16.dp)
                            .background(VigilNetTheme.GlassWhite, RoundedCornerShape(16.dp))
                            .border(1.dp, VigilNetTheme.GlassStroke, RoundedCornerShape(16.dp))
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "No active trust circles found.",
                            color = Color.White.copy(alpha = 0.4f),
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }

            items(state.circles) { circle ->
                CircleItem(info = circle)
            }
            
            item {
                Spacer(modifier = Modifier.height(40.dp))
            }
        }
    }
}

@Composable
fun CircleItem(info: String) {
    Surface(
        color = VigilNetTheme.SurfaceObsidian,
        shape = RoundedCornerShape(20.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, VigilNetTheme.GlassStroke),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(56.dp)
                    .background(VigilNetTheme.ElectricCyan.copy(alpha = 0.1f), CircleShape)
                    .border(1.dp, VigilNetTheme.ElectricCyan.copy(alpha = 0.3f), CircleShape),
                contentAlignment = Alignment.Center
            ) {
                Text(text = "🛡️", fontSize = 24.sp)
            }
            Spacer(modifier = Modifier.width(20.dp))
            Column {
                Text(
                    text = info,
                    color = Color.White,
                    fontWeight = FontWeight.Black,
                    style = MaterialTheme.typography.bodyLarge
                )
                Text(
                    text = "ENC-P2P • ACTIVE",
                    color = VigilNetTheme.NeonGreen.copy(alpha = 0.7f),
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
