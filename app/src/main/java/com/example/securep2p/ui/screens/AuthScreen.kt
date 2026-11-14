package com.example.securep2p.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.securep2p.data.IdentityManager
import com.example.securep2p.ui.theme.Accent
import com.example.securep2p.ui.theme.AccentDark
import com.example.securep2p.ui.theme.BgCard
import com.example.securep2p.ui.theme.BgDark
import com.example.securep2p.ui.theme.Border
import com.example.securep2p.ui.theme.Danger
import com.example.securep2p.ui.theme.TextPrimary
import com.example.securep2p.ui.theme.TextSecondary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun AuthScreen(
    identityManager: IdentityManager,
    onUnlocked: () -> Unit
) {
    val coroutineScope = rememberCoroutineScope()
    var exists by remember { mutableStateOf(identityManager.exists()) }
    var displayName by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var isLoading by remember { mutableStateOf(false) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDark)
            .padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = androidx.compose.foundation.BorderStroke(1.dp, Border)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Icon(
                    imageVector = Icons.Default.Security,
                    contentDescription = "Logo",
                    tint = Accent,
                    modifier = Modifier.size(56.dp)
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "SecureP2PChat",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = Accent
                )

                Text(
                    text = if (exists) "Deblochează contul existent" else "Creare cont securizat (Argon2id + X25519)",
                    fontSize = 13.sp,
                    color = TextSecondary,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(24.dp))

                if (!exists) {
                    OutlinedTextField(
                        value = displayName,
                        onValueChange = { displayName = it },
                        label = { Text("Nume utilizator") },
                        leadingIcon = {
                            Icon(Icons.Default.Person, contentDescription = null, tint = Accent)
                        },
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Accent,
                            unfocusedBorderColor = Border,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary
                        ),
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(12.dp))
                }

                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Parolă") },
                    leadingIcon = {
                        Icon(Icons.Default.Lock, contentDescription = null, tint = Accent)
                    },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Accent,
                        unfocusedBorderColor = Border,
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary
                    ),
                    modifier = Modifier.fillMaxWidth()
                )

                if (!exists) {
                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedTextField(
                        value = confirmPassword,
                        onValueChange = { confirmPassword = it },
                        label = { Text("Confirmă parola") },
                        leadingIcon = {
                            Icon(Icons.Default.Lock, contentDescription = null, tint = Accent)
                        },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
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

                if (errorMessage != null) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        text = errorMessage ?: "",
                        color = Danger,
                        fontSize = 13.sp,
                        textAlign = TextAlign.Center
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                if (isLoading) {
                    CircularProgressIndicator(
                        color = Accent,
                        modifier = Modifier.size(36.dp)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Derivare chei Argon2id...",
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                } else {
                    Button(
                        onClick = {
                            if (!exists) {
                                if (displayName.trim().isEmpty()) {
                                    errorMessage = "Introdu un nume de utilizator"
                                    return@Button
                                }
                                if (password.length < 4) {
                                    errorMessage = "Parola trebuie să aibă cel puțin 4 caractere"
                                    return@Button
                                }
                                if (password != confirmPassword) {
                                    errorMessage = "Parolele nu coincid"
                                    return@Button
                                }
                                errorMessage = null
                                isLoading = true
                                coroutineScope.launch {
                                    val ok = withContext(Dispatchers.Default) {
                                        identityManager.create(displayName, password)
                                    }
                                    isLoading = false
                                    if (ok) {
                                        onUnlocked()
                                    } else {
                                        errorMessage = "Eroare la crearea contului"
                                    }
                                }
                            } else {
                                if (password.isEmpty()) {
                                    errorMessage = "Introdu parola"
                                    return@Button
                                }
                                errorMessage = null
                                isLoading = true
                                coroutineScope.launch {
                                    val ok = withContext(Dispatchers.Default) {
                                        identityManager.unlock(password)
                                    }
                                    isLoading = false
                                    if (ok) {
                                        onUnlocked()
                                    } else {
                                        errorMessage = "Parolă incorectă"
                                    }
                                }
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(50.dp),
                        shape = RoundedCornerShape(10.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = Accent)
                    ) {
                        Text(
                            text = if (exists) "Deblochează" else "Creează Cont",
                            color = BgDark,
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp
                        )
                    }

                    if (exists) {
                        Spacer(modifier = Modifier.height(12.dp))
                        TextButton(
                            onClick = {
                                identityManager.deleteIdentity()
                                exists = false
                                password = ""
                                errorMessage = null
                            }
                        ) {
                            Text(
                                text = "Șterge contul și creează unul nou",
                                color = Danger,
                                fontSize = 12.sp
                            )
                        }
                    }
                }
            }
        }
    }
}
