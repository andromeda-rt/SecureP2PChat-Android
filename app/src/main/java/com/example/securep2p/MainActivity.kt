package com.example.securep2p

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.example.securep2p.data.IdentityManager
import com.example.securep2p.data.StorageManager
import com.example.securep2p.domain.ChatManager
import com.example.securep2p.ui.screens.AuthScreen
import com.example.securep2p.ui.screens.MainChatScreen
import com.example.securep2p.ui.theme.Securep2pTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            Securep2pTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    val identityManager = remember { IdentityManager(applicationContext) }
                    val storageManager = remember { StorageManager(applicationContext) }
                    val chatManager = remember { ChatManager(applicationContext, identityManager, storageManager) }

                    var isUnlocked by remember { mutableStateOf(identityManager.isUnlocked()) }

                    DisposableEffect(Unit) {
                        onDispose {
                            chatManager.stop()
                        }
                    }

                    if (!isUnlocked) {
                        AuthScreen(
                            identityManager = identityManager,
                            onUnlocked = {
                                isUnlocked = true
                                chatManager.start()
                            }
                        )
                    } else {
                        MainChatScreen(
                            chatManager = chatManager,
                            onLockAccount = {
                                chatManager.stop()
                                identityManager.lock()
                                isUnlocked = false
                            }
                        )
                    }
                }
            }
        }
    }
}
