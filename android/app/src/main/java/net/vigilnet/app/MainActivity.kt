package net.vigilnet.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    private val vpnStatus = mutableStateOf("VPN Stopped")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    VigilNetApp(
                        status = vpnStatus.value,
                        onStartVpn = { startVpn() },
                        onStopVpn = { stopVpn() }
                    )
                }
            }
        }
    }

    private fun startVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, 0)
        } else {
            onActivityResult(0, androidx.appcompat.app.AppCompatActivity.RESULT_OK, null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == androidx.appcompat.app.AppCompatActivity.RESULT_OK) {
            val intent = Intent(this, VigilNetVpnService::class.java)
            intent.action = VigilNetVpnService.ACTION_START
            startService(intent)
            vpnStatus.value = "VPN Running"
        }
    }

    private fun stopVpn() {
        val intent = Intent(this, VigilNetVpnService::class.java)
        intent.action = VigilNetVpnService.ACTION_STOP
        startService(intent)
        vpnStatus.value = "VPN Stopped"
    }
}

@Composable
fun VigilNetApp(status: String, onStartVpn: () -> Unit, onStopVpn: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(text = "🛡️ VigilNet", style = MaterialTheme.typography.displayMedium)
        Spacer(modifier = Modifier.height(32.dp))
        Text(text = "Status: $status")
        Spacer(modifier = Modifier.height(32.dp))
        Button(onClick = onStartVpn) {
            Text("Start VPN")
        }
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onStopVpn) {
            Text("Stop VPN")
        }
    }
}
