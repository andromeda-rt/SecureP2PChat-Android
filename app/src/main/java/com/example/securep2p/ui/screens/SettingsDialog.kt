package com.example.securep2p.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.securep2p.data.AppSettings
import com.example.securep2p.domain.ChatManager
import com.example.securep2p.ui.theme.Accent
import com.example.securep2p.ui.theme.BgCard
import com.example.securep2p.ui.theme.BgDark
import com.example.securep2p.ui.theme.Border
import com.example.securep2p.ui.theme.Danger
import com.example.securep2p.ui.theme.TextPrimary
import com.example.securep2p.ui.theme.TextSecondary

@Composable
fun SettingsDialog(
    chatManager: ChatManager,
    onDismiss: () -> Unit,
    onLockAccount: () -> Unit
) {
    val context = LocalContext.current
    val currentSettings = remember { chatManager.storageManager.loadSettings() }

    var host by remember { mutableStateOf(currentSettings.signalHost) }
    var port by remember { mutableStateOf(currentSettings.signalPort.toString()) }
    var useTls by remember { mutableStateOf(currentSettings.useTls) }
    var useTor by remember { mutableStateOf(currentSettings.useTor) }
    var torHost by remember { mutableStateOf(currentSettings.torSocksHost) }
    var torPort by remember { mutableStateOf(currentSettings.torSocksPort.toString()) }

    val devId = chatManager.identityManager.deviceId ?: "N/A"
    val fingerprint = chatManager.identityManager.getFingerprint()

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = BgCard,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Settings, contentDescription = null, tint = Accent)
                Spacer(modifier = Modifier.size(8.dp))
                Text("Setări Releu & Securitate", color = Accent, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    text = "SERVER SEMNALIZARE & RELEU",
                    color = Accent,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it },
                    label = { Text("Adresă Host Releu") },
                    placeholder = { Text("10.0.2.2 sau domeniu / .onion") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Accent,
                        unfocusedBorderColor = Border,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = port,
                    onValueChange = { port = it },
                    label = { Text("Port Releu") },
                    placeholder = { Text("37422") },
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Accent,
                        unfocusedBorderColor = Border,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Criptare TLS (recomandat)", color = TextPrimary, fontSize = 14.sp)
                    Switch(
                        checked = useTls,
                        onCheckedChange = { useTls = it },
                        colors = SwitchDefaults.colors(checkedThumbColor = Accent, checkedTrackColor = BgDark)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "REȚEA ANONIMĂ TOR (SOCKS5)",
                    color = Accent,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Conectare prin Orbot/Tor SOCKS", color = TextPrimary, fontSize = 14.sp)
                    Switch(
                        checked = useTor,
                        onCheckedChange = { useTor = it },
                        colors = SwitchDefaults.colors(checkedThumbColor = Accent, checkedTrackColor = BgDark)
                    )
                }

                if (useTor) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "Pornește Orbot și folosește host-ul/portul SOCKS configurat acolo (implicit, de obicei 127.0.0.1:9050). La host-ul releului introdu adresa .onion, iar portul trebuie să corespundă portului TCP publicat de serviciul onion. Setarea TLS trebuie să corespundă serverului.",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = torHost,
                        onValueChange = { torHost = it },
                        label = { Text("Host SOCKS Tor") },
                        placeholder = { Text("127.0.0.1") },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Accent,
                            unfocusedBorderColor = Border,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = torPort,
                        onValueChange = { torPort = it },
                        label = { Text("Port SOCKS Tor") },
                        placeholder = { Text("9050") },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Accent,
                            unfocusedBorderColor = Border,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = "IDENTITATE CRIPTOGRAFICĂ",
                    color = Accent,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text("ID Dispozitiv:", color = TextSecondary, fontSize = 12.sp)
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(BgDark, RoundedCornerShape(6.dp))
                        .border(1.dp, Border, RoundedCornerShape(6.dp))
                        .padding(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(devId, color = TextPrimary, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                        IconButton(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("Device ID", devId))
                                chatManager.showToast("ID Dispozitiv copiat")
                            },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null, tint = Accent, modifier = Modifier.size(16.dp))
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text("Amprentă Cheie (TOFU Fingerprint):", color = TextSecondary, fontSize = 12.sp)
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(BgDark, RoundedCornerShape(6.dp))
                        .border(1.dp, Border, RoundedCornerShape(6.dp))
                        .padding(horizontal = 10.dp, vertical = 6.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(fingerprint, color = Accent, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                        IconButton(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("Fingerprint", fingerprint))
                                chatManager.showToast("Amprentă copiată")
                            },
                            modifier = Modifier.size(24.dp)
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null, tint = Accent, modifier = Modifier.size(16.dp))
                        }
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))

                OutlinedButton(
                    onClick = {
                        onDismiss()
                        onLockAccount()
                    },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Danger),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Danger),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.Lock, contentDescription = null, tint = Danger, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.size(8.dp))
                    Text("Blochează Contul (Logout)")
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val p = port.toIntOrNull() ?: 37422
                    val tp = torPort.toIntOrNull() ?: 9050
                    val newSettings = AppSettings(
                        signalHost = host.trim().ifEmpty { "10.0.2.2" },
                        signalPort = p,
                        useTls = useTls,
                        useTor = useTor,
                        torSocksHost = torHost.trim().ifEmpty { "127.0.0.1" },
                        torSocksPort = tp
                    )
                    chatManager.updateSettingsAndReconnect(newSettings)
                    onDismiss()
                },
                colors = ButtonDefaults.buttonColors(containerColor = Accent)
            ) {
                Text("Salvează & Conectează", color = BgDark, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Anulează", color = TextSecondary)
            }
        }
    )
}
