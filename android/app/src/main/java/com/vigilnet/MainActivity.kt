package com.vigilnet

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.*
import com.vigilnet.service.VigilNetVpnService
import com.vigilnet.ui.screens.*
import com.vigilnet.ui.theme.VigilNetTheme

/**
 * Main Activity for VigilNet Android Application
 * 
 * Entry point that sets up:
 * - Material3 theme with dark mode
 * - Bottom navigation between screens
 * - VPN service binding and lifecycle management
 * - Permission handling for VPN and notifications
 */
class MainActivity : ComponentActivity() {
    
    companion object {
        private const val TAG = "MainActivity"
    }
    
    private var vpnService: VigilNetVpnService? = null
    private var serviceBound = false
    
    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as VigilNetVpnService.LocalBinder
            vpnService = binder.getService()
            serviceBound = true
        }
        
        override fun onServiceDisconnected(name: ComponentName?) {
            vpnService = null
            serviceBound = false
        }
    }
    
    // VPN permission launcher
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            // VPN permission granted, start the service
            startVpnService()
        }
    }
    
    // Notification permission launcher (Android 13+)
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        // Handle notification permission result if needed
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        
        setContent {
            VigilNetTheme {
                VigilNetApp(
                    onStartVpn = { requestVpnPermission() },
                    onStopVpn = { stopVpnService() }
                )
            }
        }
    }
    
    override fun onStart() {
        super.onStart()
        // Bind to VPN service
        Intent(this, VigilNetVpnService::class.java).also { intent ->
            bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        }
    }
    
    override fun onStop() {
        super.onStop()
        // Unbind from VPN service
        if (serviceBound) {
            unbindService(serviceConnection)
            serviceBound = false
        }
    }
    
    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            // VPN permission already granted
            startVpnService()
        }
    }
    
    private fun startVpnService() {
        val intent = Intent(this, VigilNetVpnService::class.java).apply {
            action = VigilNetVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(this, intent)
    }
    
    private fun stopVpnService() {
        val intent = Intent(this, VigilNetVpnService::class.java).apply {
            action = VigilNetVpnService.ACTION_STOP
        }
        startService(intent)
    }
}

/**
 * Main app composable with bottom navigation
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VigilNetApp(
    onStartVpn: () -> Unit,
    onStopVpn: () -> Unit
) {
    val navController = rememberNavController()
    
    // Navigation items
    val items = listOf(
        Screen.Home,
        Screen.Agents,
        Screen.Circles,
        Screen.Mesh
    )
    
    Scaffold(
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
                tonalElevation = 0.dp
            ) {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination
                
                items.forEach { screen ->
                    NavigationBarItem(
                        icon = { Icon(screen.icon, contentDescription = screen.title) },
                        label = { Text(screen.title) },
                        selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true,
                        onClick = {
                            navController.navigate(screen.route) {
                                // Pop up to the start destination of the graph to
                                // avoid building up a large stack of destinations
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                // Avoid multiple copies of the same destination when
                                // reselecting the same item
                                launchSingleTop = true
                                // Restore state when reselecting a previously selected item
                                restoreState = true
                            }
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.primary,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                            indicatorColor = MaterialTheme.colorScheme.primaryContainer
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Home.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Screen.Home.route) {
                HomeScreen(
                    onStartVpn = onStartVpn,
                    onStopVpn = onStopVpn
                )
            }
            composable(Screen.Agents.route) {
                AgentsScreen()
            }
            composable(Screen.Circles.route) {
                CirclesScreen()
            }
            composable(Screen.Mesh.route) {
                MeshScreen()
            }
        }
    }
}

/**
 * Screen definitions for navigation
 */
sealed class Screen(
    val route: String,
    val title: String,
    val icon: androidx.compose.ui.graphics.vector.ImageVector
) {
    object Home : Screen("home", "Home", Icons.Default.Home)
    object Agents : Screen("agents", "Agents", Icons.Default.SmartToy)
    object Circles : Screen("circles", "Circles", Icons.Default.Groups)
    object Mesh : Screen("mesh", "Mesh", Icons.Default.Hub)
}
