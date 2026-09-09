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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vigilnet.ffi.CircleInfo
import com.vigilnet.ffi.CircleType
import com.vigilnet.ui.theme.*
import com.vigilnet.ui.viewmodels.CircleViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CirclesScreen(
    viewModel: CircleViewModel = viewModel()
) {
    val circles by viewModel.circles.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    val showCreateDialog by viewModel.showCreateDialog.collectAsState()
    val showJoinDialog by viewModel.showJoinDialog.collectAsState()
    val selectedCircle by viewModel.selectedCircle.collectAsState()
    val inviteCode by viewModel.inviteCode.collectAsState()
    
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
                title = { Text("Circles") },
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
                .padding(16.dp)
        ) {
            // Action Buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(
                    onClick = { viewModel.showCreateDialog() },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(Icons.Default.Add, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Create")
                }
                
                OutlinedButton(
                    onClick = { viewModel.showJoinDialog() },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Icon(Icons.Default.Login, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Join")
                }
            }
            
            Spacer(modifier = Modifier.height(24.dp))
            
            // Circles List
            if (circles.isEmpty()) {
                EmptyCirclesState()
            } else {
                Text(
                    text = "Your Circles",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(bottom = 12.dp)
                )
                
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(circles) { circle ->
                        CircleCard(
                            circle = circle,
                            viewModel = viewModel,
                            onClick = { viewModel.selectCircle(circle) }
                        )
                    }
                }
            }
        }
    }
    
    // Create Circle Dialog
    if (showCreateDialog) {
        CreateCircleDialog(
            onDismiss = { viewModel.hideCreateDialog() },
            onCreate = { name, type, maxMembers ->
                viewModel.createCircle(name, type, maxMembers)
            },
            isLoading = isLoading
        )
    }
    
    // Join Circle Dialog
    if (showJoinDialog) {
        JoinCircleDialog(
            onDismiss = { viewModel.hideJoinDialog() },
            onJoin = { inviteCode ->
                viewModel.joinCircle(inviteCode)
            },
            isLoading = isLoading
        )
    }
    
    // Circle Details Dialog
    if (selectedCircle != null) {
        CircleDetailsDialog(
            circle = selectedCircle!!,
            viewModel = viewModel,
            onDismiss = { viewModel.selectCircle(null) }
        )
    }
    
    // Show Invite Code Dialog
    if (inviteCode != null) {
        InviteCodeDialog(
            inviteCode = inviteCode!!,
            onDismiss = { viewModel.clearInviteCode() }
        )
    }
}

@Composable
fun CircleCard(
    circle: CircleInfo,
    viewModel: CircleViewModel,
    onClick: () -> Unit
) {
    val typeColor = when (circle.type) {
        CircleType.PUBLIC -> VigilNetPrimary
        CircleType.PRIVATE -> VigilNetSecondary
        CircleType.AUDIT -> VigilNetTertiary
        else -> TextTertiaryDark
    }
    
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = SurfaceDark
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Circle type indicator
                    Box(
                        modifier = Modifier
                            .size(12.dp)
                            .clip(CircleShape)
                            .background(typeColor)
                    )
                    
                    Spacer(modifier = Modifier.width(12.dp))
                    
                    Text(
                        text = circle.name,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                
                // Member count
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
                        text = "${circle.memberCount}/${circle.maxMembers}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = TextSecondaryDark
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = viewModel.getCircleTypeName(circle.type),
                    style = MaterialTheme.typography.bodySmall,
                    color = typeColor
                )
                
                Text(
                    text = "Created ${viewModel.formatTimestamp(circle.createdAt)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = TextTertiaryDark
                )
            }
        }
    }
}

@Composable
fun EmptyCirclesState() {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Default.Group,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = TextTertiaryDark
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Text(
            text = "No Circles Yet",
            style = MaterialTheme.typography.titleLarge,
            color = TextSecondaryDark
        )
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Text(
            text = "Create or join a circle to get started",
            style = MaterialTheme.typography.bodyMedium,
            color = TextTertiaryDark
        )
    }
}

@Composable
fun CreateCircleDialog(
    onDismiss: () -> Unit,
    onCreate: (String, Int, Int) -> Unit,
    isLoading: Boolean
) {
    var name by remember { mutableStateOf("") }
    var selectedType by remember { mutableStateOf(CircleType.PUBLIC) }
    var maxMembers by remember { mutableStateOf("50") }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Create Circle") },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Circle Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Text(
                    text = "Circle Type",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                listOf(
                    CircleType.PUBLIC to "Public - Anyone can join",
                    CircleType.PRIVATE to "Private - Invite only",
                    CircleType.AUDIT to "Audit - Immutable records"
                ).forEach { (type, description) ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = selectedType == type,
                            onClick = { selectedType = type }
                        )
                        Column(modifier = Modifier.padding(start = 8.dp)) {
                            Text(
                                text = description.substringBefore(" - "),
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Text(
                                text = description.substringAfter(" - "),
                                style = MaterialTheme.typography.bodySmall,
                                color = TextTertiaryDark
                            )
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedTextField(
                    value = maxMembers,
                    onValueChange = { maxMembers = it.filter { it.isDigit() } },
                    label = { Text("Max Members") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onCreate(name, selectedType, maxMembers.toIntOrNull() ?: 50)
                },
                enabled = name.isNotBlank() && !isLoading
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                } else {
                    Text("Create")
                }
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
fun JoinCircleDialog(
    onDismiss: () -> Unit,
    onJoin: (String) -> Unit,
    isLoading: Boolean
) {
    var inviteCode by remember { mutableStateOf("") }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Join Circle") },
        text = {
            Column {
                Text(
                    text = "Enter the invite code shared with you",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondaryDark,
                    modifier = Modifier.padding(bottom = 16.dp)
                )
                
                OutlinedTextField(
                    value = inviteCode,
                    onValueChange = { inviteCode = it },
                    label = { Text("Invite Code") },
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onJoin(inviteCode) },
                enabled = inviteCode.isNotBlank() && !isLoading
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                } else {
                    Text("Join")
                }
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
fun CircleDetailsDialog(
    circle: CircleInfo,
    viewModel: CircleViewModel,
    onDismiss: () -> Unit
) {
    var showCreateInvite by remember { mutableStateOf(false) }
    var showSendMessage by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    
    if (showCreateInvite) {
        CreateInviteDialog(
            circleName = circle.name,
            onDismiss = { showCreateInvite = false },
            onCreate = { threshold, numShares, validityHours ->
                viewModel.createInvite(circle.id, threshold, numShares, validityHours)
                showCreateInvite = false
            }
        )
        return
    }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(circle.name) },
        text = {
            Column {
                // Circle info
                DetailRow(label = "Type", value = viewModel.getCircleTypeName(circle.type))
                DetailRow(label = "Members", value = "${circle.memberCount}/${circle.maxMembers}")
                DetailRow(label = "Created", value = viewModel.formatTimestamp(circle.createdAt))
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Divider()
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Actions
                if (showSendMessage) {
                    OutlinedTextField(
                        value = message,
                        onValueChange = { message = it },
                        label = { Text("Message to circle") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                viewModel.sendToCircle(circle.id, message)
                                message = ""
                                showSendMessage = false
                            },
                            enabled = message.isNotBlank(),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Send")
                        }
                        
                        OutlinedButton(
                            onClick = { showSendMessage = false },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Cancel")
                        }
                    }
                } else {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { showCreateInvite = true },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Create Invite")
                        }
                        
                        OutlinedButton(
                            onClick = { showSendMessage = true },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text("Send Message")
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    OutlinedButton(
                        onClick = { viewModel.leaveCircle(circle.id) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = StatusError
                        )
                    ) {
                        Text("Leave Circle")
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

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = TextSecondaryDark
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
fun CreateInviteDialog(
    circleName: String,
    onDismiss: () -> Unit,
    onCreate: (Int, Int, Int) -> Unit
) {
    var threshold by remember { mutableStateOf("2") }
    var numShares by remember { mutableStateOf("3") }
    var validityHours by remember { mutableStateOf("24") }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Create Invite for $circleName") },
        text = {
            Column {
                Text(
                    text = "Configure the invite parameters:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondaryDark,
                    modifier = Modifier.padding(bottom = 16.dp)
                )
                
                OutlinedTextField(
                    value = threshold,
                    onValueChange = { threshold = it.filter { it.isDigit() } },
                    label = { Text("Threshold (min shares needed)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                OutlinedTextField(
                    value = numShares,
                    onValueChange = { numShares = it.filter { it.isDigit() } },
                    label = { Text("Number of Shares") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                
                Spacer(modifier = Modifier.height(8.dp))
                
                OutlinedTextField(
                    value = validityHours,
                    onValueChange = { validityHours = it.filter { it.isDigit() } },
                    label = { Text("Validity (hours)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onCreate(
                        threshold.toIntOrNull() ?: 2,
                        numShares.toIntOrNull() ?: 3,
                        validityHours.toIntOrNull() ?: 24
                    )
                },
                enabled = threshold.isNotBlank() && numShares.isNotBlank() && validityHours.isNotBlank()
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
fun InviteCodeDialog(
    inviteCode: String,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Invite Created") },
        text = {
            Column {
                Text(
                    text = "Share this invite code with trusted members:",
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondaryDark,
                    modifier = Modifier.padding(bottom = 16.dp)
                )
                
                Surface(
                    color = SurfaceVariantDark,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = inviteCode,
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text("Done")
            }
        }
    )
}
