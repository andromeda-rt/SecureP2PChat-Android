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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
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
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.securep2p.domain.ChatManager
import com.example.securep2p.ui.theme.Accent
import com.example.securep2p.ui.theme.BgCard
import com.example.securep2p.ui.theme.BgDark
import com.example.securep2p.ui.theme.Border
import com.example.securep2p.ui.theme.Success
import com.example.securep2p.ui.theme.TextPrimary
import com.example.securep2p.ui.theme.TextSecondary

@Composable
fun GeneratePairCodeDialog(
    chatManager: ChatManager,
    pairCode: String?,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var copied by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = BgCard,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Key, contentDescription = null, tint = Accent)
                Spacer(modifier = Modifier.size(8.dp))
                Text("Cod de Asociere Chat (1-la-1)", color = Accent, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            }
        },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "Trimite acest cod prietenului tău pentru a vă conecta prin releu:",
                    color = TextSecondary,
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(16.dp))

                if (pairCode != null) {
                    Box(
                        modifier = Modifier
                            .background(BgDark, RoundedCornerShape(12.dp))
                            .border(1.dp, Accent, RoundedCornerShape(12.dp))
                            .padding(vertical = 12.dp, horizontal = 24.dp)
                    ) {
                        Text(
                            text = pairCode.chunked(3).joinToString(" "),
                            color = Accent,
                            fontSize = 32.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            letterSpacing = 4.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedButton(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("Pair Code", pairCode))
                            copied = true
                        },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Accent),
                        border = ButtonDefaults.outlinedButtonBorder.copy(brush = androidx.compose.ui.graphics.SolidColor(Accent))
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.size(8.dp))
                        Text(if (copied) "Copiat în clipboard!" else "Copiază codul")
                    }

                    Spacer(modifier = Modifier.height(16.dp))

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), color = Accent, strokeWidth = 2.dp)
                        Spacer(modifier = Modifier.size(8.dp))
                        Text(
                            "Așteptare ca peer-ul să introducă codul...",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                    }
                } else {
                    CircularProgressIndicator(color = Accent)
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Se generează codul pe releu...", color = TextSecondary, fontSize = 12.sp)
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Închide", color = Accent)
            }
        }
    )
}

@Composable
fun JoinPairCodeDialog(
    chatManager: ChatManager,
    onDismiss: () -> Unit
) {
    var code by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = BgCard,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.QrCode, contentDescription = null, tint = Accent)
                Spacer(modifier = Modifier.size(8.dp))
                Text("Intră cu Cod Chat", color = Accent, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            }
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "Introdu codul de 6 caractere primit de la celălalt utilizator:",
                    color = TextSecondary,
                    fontSize = 13.sp
                )

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = code,
                    onValueChange = { if (it.length <= 8) code = it.uppercase() },
                    placeholder = { Text("Ex: A7B2C9") },
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
        },
        confirmButton = {
            Button(
                onClick = {
                    if (code.trim().isNotEmpty()) {
                        chatManager.joinPairCode(code.trim())
                        onDismiss()
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = Accent)
            ) {
                Text("Conectare (Pair)", color = BgDark, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Anulează", color = TextSecondary)
            }
        }
    )
}

@Composable
fun CreateGroupDialog(
    chatManager: ChatManager,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    var groupName by remember { mutableStateOf("") }
    var createdInviteCode by remember { mutableStateOf<String?>(null) }
    var isCreating by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = BgCard,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Group, contentDescription = null, tint = Accent)
                Spacer(modifier = Modifier.size(8.dp))
                Text("Creează Grup Nou", color = Accent, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            }
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                if (createdInviteCode == null) {
                    Text(
                        text = "Introdu numele grupului pe care dorești să îl creezi:",
                        color = TextSecondary,
                        fontSize = 13.sp
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    OutlinedTextField(
                        value = groupName,
                        onValueChange = { groupName = it },
                        placeholder = { Text("Ex: Grupul Nostru") },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Accent,
                            unfocusedBorderColor = Border,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )
                } else {
                    Text(
                        text = "Grup creat cu succes! Trimite acest cod de invitație membrilor:",
                        color = Success,
                        fontSize = 13.sp
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(BgDark, RoundedCornerShape(8.dp))
                            .border(1.dp, Accent, RoundedCornerShape(8.dp))
                            .padding(12.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = createdInviteCode ?: "",
                            color = Accent,
                            fontSize = 24.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedButton(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            clipboard.setPrimaryClip(ClipData.newPlainText("Group Code", createdInviteCode))
                        },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Accent),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.size(8.dp))
                        Text("Copiază Codul de Invitație")
                    }
                }
            }
        },
        confirmButton = {
            if (createdInviteCode == null) {
                Button(
                    onClick = {
                        if (groupName.trim().isNotEmpty() && !isCreating) {
                            isCreating = true
                            chatManager.createGroup(groupName.trim()) { grp ->
                                isCreating = false
                                if (grp != null) {
                                    createdInviteCode = grp.inviteCode
                                }
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = Accent)
                ) {
                    if (isCreating) {
                        CircularProgressIndicator(modifier = Modifier.size(16.dp), color = BgDark)
                    } else {
                        Text("Creează", color = BgDark, fontWeight = FontWeight.Bold)
                    }
                }
            } else {
                Button(
                    onClick = onDismiss,
                    colors = ButtonDefaults.buttonColors(containerColor = Accent)
                ) {
                    Text("Gata", color = BgDark, fontWeight = FontWeight.Bold)
                }
            }
        },
        dismissButton = {
            if (createdInviteCode == null) {
                TextButton(onClick = onDismiss) {
                    Text("Anulează", color = TextSecondary)
                }
            }
        }
    )
}

@Composable
fun JoinGroupDialog(
    chatManager: ChatManager,
    onDismiss: () -> Unit
) {
    var inviteCode by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = BgCard,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Group, contentDescription = null, tint = Accent)
                Spacer(modifier = Modifier.size(8.dp))
                Text("Intră în Grup", color = Accent, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            }
        },
        text = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = "Introdu codul de invitație primit pentru a te alătura grupului:",
                    color = TextSecondary,
                    fontSize = 13.sp
                )

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedTextField(
                    value = inviteCode,
                    onValueChange = { inviteCode = it.uppercase() },
                    placeholder = { Text("Ex: GRP123") },
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
        },
        confirmButton = {
            Button(
                onClick = {
                    if (inviteCode.trim().isNotEmpty()) {
                        chatManager.joinGroup(inviteCode.trim())
                        onDismiss()
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = Accent)
            ) {
                Text("Alătură-te", color = BgDark, fontWeight = FontWeight.Bold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Anulează", color = TextSecondary)
            }
        }
    )
}
