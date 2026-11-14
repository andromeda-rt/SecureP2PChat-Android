package com.example.securep2p.ui.screens

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.media.MediaRecorder
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.widget.Toast
import android.webkit.MimeTypeMap
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.GroupAdd
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import androidx.core.content.ContextCompat
import com.example.securep2p.data.ChatMessage
import com.example.securep2p.data.Contact
import com.example.securep2p.data.GroupChat
import com.example.securep2p.domain.ChatManager
import com.example.securep2p.protocol.Constants
import com.example.securep2p.ui.theme.Accent
import com.example.securep2p.ui.theme.AccentDark
import com.example.securep2p.ui.theme.BgCard
import com.example.securep2p.ui.theme.BgDark
import com.example.securep2p.ui.theme.BgSecondary
import com.example.securep2p.ui.theme.Border
import com.example.securep2p.ui.theme.BubbleIn
import com.example.securep2p.ui.theme.BubbleOut
import com.example.securep2p.ui.theme.Danger
import com.example.securep2p.ui.theme.Success
import com.example.securep2p.ui.theme.TextPrimary
import com.example.securep2p.ui.theme.TextSecondary
import com.example.securep2p.ui.theme.Warning
import java.io.File
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainChatScreen(
    chatManager: ChatManager,
    onLockAccount: () -> Unit
) {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    val isLandscape = configuration.orientation == Configuration.ORIENTATION_LANDSCAPE

    val peers by chatManager.activePeers.collectAsState()
    val groups by chatManager.activeGroups.collectAsState()
    val selectedPeerId by chatManager.selectedPeerId.collectAsState()
    val messages by chatManager.currentMessages.collectAsState()
    val connectionState by chatManager.connectionState.collectAsState()
    val generatedPairCode by chatManager.generatedPairCode.collectAsState()
    val statusNotification by chatManager.statusNotification.collectAsState()
    val transferProgress by chatManager.transferProgress.collectAsState()

    val screenScope = rememberCoroutineScope()
    var showSettingsDialog by remember { mutableStateOf(false) }
    var showGeneratePairDialog by remember { mutableStateOf(false) }
    var showJoinPairDialog by remember { mutableStateOf(false) }
    var showCreateGroupDialog by remember { mutableStateOf(false) }
    var showJoinGroupDialog by remember { mutableStateOf(false) }
    var showChatMenu by remember { mutableStateOf(false) }
    var showGroupMenu by remember { mutableStateOf(false) }
    var showClearConversationDialog by remember { mutableStateOf(false) }
    var showDeleteChatDialog by remember { mutableStateOf(false) }

    var textInput by remember { mutableStateOf("") }
    var isRecordingVoice by remember { mutableStateOf(false) }
    var voiceRecorder by remember { mutableStateOf<MediaRecorder?>(null) }
    var voiceRecordingFile by remember { mutableStateOf<File?>(null) }
    val listState = rememberLazyListState()

    // Handle back button on mobile portrait to close open conversation
    BackHandler(enabled = !isLandscape && selectedPeerId != null) {
        chatManager.selectPeer(null)
    }

    // File picker launcher
    fun startVoiceRecording() {
        val outputFile = File(context.cacheDir, "voice_${System.currentTimeMillis()}.m4a")
        val recorder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            MediaRecorder(context)
        } else {
            @Suppress("DEPRECATION")
            MediaRecorder()
        }
        try {
            recorder.setAudioSource(MediaRecorder.AudioSource.MIC)
            recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
            recorder.setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
            recorder.setAudioSamplingRate(44_100)
            recorder.setAudioEncodingBitRate(96_000)
            recorder.setOutputFile(outputFile.absolutePath)
            recorder.prepare()
            recorder.start()
            voiceRecorder = recorder
            voiceRecordingFile = outputFile
            isRecordingVoice = true
            chatManager.showToast("Înregistrare pornită — apasă Stop pentru a trimite")
        } catch (e: Exception) {
            recorder.release()
            outputFile.delete()
            chatManager.showToast("Nu s-a putut porni înregistrarea: ${e.localizedMessage}")
        }
    }

    fun stopVoiceRecording() {
        val recorder = voiceRecorder
        val file = voiceRecordingFile
        voiceRecorder = null
        voiceRecordingFile = null
        isRecordingVoice = false
        if (recorder == null || file == null) return

        var recordingCompleted = true
        try {
            recorder.stop()
        } catch (e: Exception) {
            recordingCompleted = false
            file.delete()
            chatManager.showToast("Înregistrarea este prea scurtă sau a eșuat")
        } finally {
            recorder.release()
        }
        if (!recordingCompleted) return
        if (!file.exists() || file.length() == 0L) {
            file.delete()
            return
        }
        screenScope.launch {
            try {
                val audioBytes = withContext(Dispatchers.IO) { file.readBytes() }
                chatManager.sendFile(file.name, audioBytes)
                file.delete()
            } catch (e: Exception) {
                file.delete()
                chatManager.showToast("Nu s-a putut trimite mesajul vocal: ${e.localizedMessage}")
            }
        }
    }

    val audioPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) startVoiceRecording()
        else chatManager.showToast("Permite accesul la microfon pentru a înregistra un mesaj vocal")
    }

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            screenScope.launch {
                try {
                    val (filename, bytes) = withContext(Dispatchers.IO) {
                        var selectedName = "attachment_${System.currentTimeMillis()}"
                        var selectedSize = -1L
                        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                            val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                            val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                            if (cursor.moveToFirst()) {
                                if (nameIndex != -1) cursor.getString(nameIndex)?.let { selectedName = it }
                                if (sizeIndex != -1) selectedSize = cursor.getLong(sizeIndex)
                            }
                        }
                        require(selectedSize <= Constants.MAX_FILE_SIZE) {
                            "Fișierul depășește limita de 50 MB"
                        }
                        val output = ByteArrayOutputStream()
                        context.contentResolver.openInputStream(uri)?.use { input ->
                            val buffer = ByteArray(16 * 1024)
                            var total = 0L
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                total += count
                                require(total <= Constants.MAX_FILE_SIZE) {
                                    "Fișierul depășește limita de 50 MB"
                                }
                                output.write(buffer, 0, count)
                            }
                        } ?: error("Fișierul nu poate fi citit")
                        selectedName to output.toByteArray()
                    }
                    chatManager.sendFile(filename, bytes)
                } catch (e: Exception) {
                    chatManager.showToast("Eroare la atașament: ${e.localizedMessage}")
                }
            }
        }
    }

    DisposableEffect(Unit) {
        onDispose {
            voiceRecorder?.let { recorder ->
                runCatching { recorder.stop() }
                recorder.release()
            }
            voiceRecordingFile?.delete()
        }
    }

    LaunchedEffect(messages.size) {
        if (messages.isNotEmpty()) {
            listState.animateScrollToItem(messages.size - 1)
        }
    }

    val selectedPeer = peers.find { it.deviceId == selectedPeerId }
    val selectedGroup = groups.find { it.groupId == selectedPeerId }

    Scaffold(
        snackbarHost = {},
        topBar = {
            Column {
                TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (!isLandscape && (selectedPeer != null || selectedGroup != null)) {
                            IconButton(
                                onClick = { chatManager.selectPeer(null) },
                                modifier = Modifier.size(36.dp)
                            ) {
                                Icon(
                                    imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                                    contentDescription = "Înapoi",
                                    tint = Accent
                                )
                            }
                            Spacer(modifier = Modifier.width(4.dp))
                        }

                        Text(
                            text = "SecureP2P",
                            fontWeight = FontWeight.Bold,
                            color = Accent,
                            fontSize = 18.sp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        // Relay connection pill
                        val (statusColor, statusBg) = when {
                            connectionState.startsWith("Conectat") -> Pair(Success, Success.copy(alpha = 0.15f))
                            connectionState.startsWith("În curs") -> Pair(Warning, Warning.copy(alpha = 0.15f))
                            else -> Pair(Danger, Danger.copy(alpha = 0.15f))
                        }
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(12.dp))
                                .background(statusBg)
                                .clickable { chatManager.start() }
                                .padding(horizontal = 7.dp, vertical = 3.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier
                                        .size(6.dp)
                                        .clip(CircleShape)
                                        .background(statusColor)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    text = if (connectionState.startsWith("Conectat")) "Releu OK" else connectionState,
                                    color = statusColor,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Medium
                                )
                            }
                        }
                    }
                },
                actions = {
                    // Chat Code button with dropdown menu
                    Box {
                        IconButton(
                            onClick = { showChatMenu = true },
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(Icons.Default.Key, contentDescription = "Cod Chat", tint = Accent)
                        }
                        DropdownMenu(
                            expanded = showChatMenu,
                            onDismissRequest = { showChatMenu = false },
                            modifier = Modifier.background(BgCard)
                        ) {
                            DropdownMenuItem(
                                text = { Text("Generează Cod Chat (1-la-1)", color = TextPrimary) },
                                leadingIcon = { Icon(Icons.Default.Key, contentDescription = null, tint = Accent) },
                                onClick = {
                                    showChatMenu = false
                                    chatManager.generatePairCode()
                                    showGeneratePairDialog = true
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Intră cu Cod Chat", color = TextPrimary) },
                                leadingIcon = { Icon(Icons.Default.QrCode, contentDescription = null, tint = Accent) },
                                onClick = {
                                    showChatMenu = false
                                    showJoinPairDialog = true
                                }
                            )
                        }
                    }

                    // Group button with dropdown menu
                    Box {
                        IconButton(
                            onClick = { showGroupMenu = true },
                            modifier = Modifier.size(36.dp)
                        ) {
                            Icon(Icons.Default.Group, contentDescription = "Grup", tint = Accent)
                        }
                        DropdownMenu(
                            expanded = showGroupMenu,
                            onDismissRequest = { showGroupMenu = false },
                            modifier = Modifier.background(BgCard)
                        ) {
                            DropdownMenuItem(
                                text = { Text("Creează Grup Nou", color = TextPrimary) },
                                leadingIcon = { Icon(Icons.Default.GroupAdd, contentDescription = null, tint = Accent) },
                                onClick = {
                                    showGroupMenu = false
                                    showCreateGroupDialog = true
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Intră în Grup cu Cod", color = TextPrimary) },
                                leadingIcon = { Icon(Icons.Default.Group, contentDescription = null, tint = Accent) },
                                onClick = {
                                    showGroupMenu = false
                                    showJoinGroupDialog = true
                                }
                            )
                        }
                    }

                    // Settings button
                    IconButton(
                        onClick = { showSettingsDialog = true },
                        modifier = Modifier.size(36.dp)
                    ) {
                        Icon(Icons.Default.Settings, contentDescription = "Setări", tint = Accent)
                    }
                },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = BgDark)
                )
                statusNotification?.let { message ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 4.dp)
                            .clip(RoundedCornerShape(10.dp))
                            .background(BgCard)
                            .border(1.dp, Border, RoundedCornerShape(10.dp))
                            .padding(horizontal = 12.dp, vertical = 9.dp)
                    ) {
                        Text(
                            text = message,
                            color = TextPrimary,
                            fontSize = 12.sp,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
    ) { paddingValues ->
        if (isLandscape) {
            // LANDSCAPE: SIDE-BY-SIDE (desktop-like)
            Row(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .background(BgDark)
            ) {
                // LEFT COLUMN: PEER BUBBLES
                Column(
                    modifier = Modifier
                        .width(82.dp)
                        .fillMaxHeight()
                        .background(BgSecondary)
                        .border(width = 0.5.dp, color = Border)
                        .padding(vertical = 8.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "PEERS",
                        color = Accent,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    LazyColumn(
                        modifier = Modifier.weight(1f),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        items(peers) { peer ->
                            PeerBubbleItem(
                                displayName = peer.displayName,
                                isOnline = peer.isOnline,
                                isSelected = peer.deviceId == selectedPeerId,
                                isGroup = false,
                                onClick = { chatManager.selectPeer(peer.deviceId) }
                            )
                        }

                        items(groups) { group ->
                            PeerBubbleItem(
                                displayName = group.name,
                                isOnline = true,
                                isSelected = group.groupId == selectedPeerId,
                                isGroup = true,
                                onClick = { chatManager.selectPeer(group.groupId) }
                            )
                        }

                        if (peers.isEmpty() && groups.isEmpty()) {
                            item {
                                Box(
                                    modifier = Modifier
                                        .padding(horizontal = 6.dp)
                                        .clickable { showJoinPairDialog = true },
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        text = "Niciun peer.\nCod Chat",
                                        color = TextSecondary,
                                        fontSize = 10.sp,
                                        textAlign = TextAlign.Center
                                    )
                                }
                            }
                        }
                    }
                }

                // RIGHT: CHAT PANE
                Box(modifier = Modifier.weight(1f).fillMaxHeight()) {
                    if (selectedPeer != null || selectedGroup != null) {
                        ChatPane(
                            title = selectedPeer?.displayName ?: selectedGroup?.name ?: "",
                            subtitle = if (selectedPeer != null) {
                                "Amprentă: ${selectedPeer.fingerprint.take(19)}... • Canal E2EE"
                            } else {
                                "Grup (${selectedGroup?.members?.size ?: 1} membri) • Cod: ${selectedGroup?.inviteCode}"
                            },
                            isGroup = selectedGroup != null,
                            transferProgress = transferProgress,
                            messages = messages,
                            textInput = textInput,
                            onTextInputChange = { textInput = it },
                            onSendText = {
                                if (textInput.trim().isNotEmpty()) {
                                    chatManager.sendTextMessage(textInput.trim())
                                    textInput = ""
                                }
                            },
                            onPickFile = { filePickerLauncher.launch(arrayOf("*/*")) },
                            isRecordingVoice = isRecordingVoice,
                            onRecordVoice = {
                                if (isRecordingVoice) {
                                    stopVoiceRecording()
                                } else if (ContextCompat.checkSelfPermission(
                                        context,
                                        Manifest.permission.RECORD_AUDIO
                                    ) == PackageManager.PERMISSION_GRANTED
                                ) {
                                    startVoiceRecording()
                                } else {
                                    audioPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                                }
                            },
                            onClearConversation = { showClearConversationDialog = true },
                            onDeleteChat = { showDeleteChatDialog = true },
                            listState = listState,
                            context = context
                        )
                    } else {
                        EmptyChatState(
                            onGenerateCode = {
                                chatManager.generatePairCode()
                                showGeneratePairDialog = true
                            },
                            onJoinCode = { showJoinPairDialog = true },
                            onCreateGroup = { showCreateGroupDialog = true }
                        )
                    }
                }
            }
        } else {
            // PORTRAIT (TELEFON DREPT): ADAPTIVE TOP HORIZONTAL BUBBLES + FULLSCREEN CHAT
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(paddingValues)
                    .background(BgDark)
            ) {
                // TOP HORIZONTAL PEER BUBBLES BAR
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(BgSecondary)
                        .border(width = 0.5.dp, color = Border)
                        .padding(vertical = 6.dp, horizontal = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    LazyRow(
                        modifier = Modifier.weight(1f),
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Quick add / pair bubble
                        item {
                            Column(
                                modifier = Modifier
                                    .width(58.dp)
                                    .clickable { showChatMenu = true },
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(46.dp)
                                        .clip(CircleShape)
                                        .background(BgCard)
                                        .border(1.dp, Border, CircleShape),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Key,
                                        contentDescription = "Adaugă",
                                        tint = Accent,
                                        modifier = Modifier.size(20.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.height(2.dp))
                                Text(
                                    text = "+ Adaugă",
                                    color = TextSecondary,
                                    fontSize = 10.sp,
                                    maxLines = 1,
                                    textAlign = TextAlign.Center
                                )
                            }
                        }

                        // List 1-on-1 Contacts
                        items(peers) { peer ->
                            PeerBubbleItem(
                                displayName = peer.displayName,
                                isOnline = peer.isOnline,
                                isSelected = peer.deviceId == selectedPeerId,
                                isGroup = false,
                                onClick = { chatManager.selectPeer(peer.deviceId) }
                            )
                        }

                        // List Groups
                        items(groups) { group ->
                            PeerBubbleItem(
                                displayName = group.name,
                                isOnline = true,
                                isSelected = group.groupId == selectedPeerId,
                                isGroup = true,
                                onClick = { chatManager.selectPeer(group.groupId) }
                            )
                        }
                    }
                }

                // MAIN CONTENT: CHAT IF SELECTED OR OVERVIEW / EMPTY STATE
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                ) {
                    if (selectedPeer != null || selectedGroup != null) {
                        ChatPane(
                            title = selectedPeer?.displayName ?: selectedGroup?.name ?: "",
                            subtitle = if (selectedPeer != null) {
                                "Amprentă: ${selectedPeer.fingerprint.take(19)}... • Canal E2EE"
                            } else {
                                "Grup (${selectedGroup?.members?.size ?: 1} membri) • Cod: ${selectedGroup?.inviteCode}"
                            },
                            isGroup = selectedGroup != null,
                            transferProgress = transferProgress,
                            messages = messages,
                            textInput = textInput,
                            onTextInputChange = { textInput = it },
                            onSendText = {
                                if (textInput.trim().isNotEmpty()) {
                                    chatManager.sendTextMessage(textInput.trim())
                                    textInput = ""
                                }
                            },
                            onPickFile = { filePickerLauncher.launch(arrayOf("*/*")) },
                            isRecordingVoice = isRecordingVoice,
                            onRecordVoice = {
                                if (isRecordingVoice) {
                                    stopVoiceRecording()
                                } else if (ContextCompat.checkSelfPermission(
                                        context,
                                        Manifest.permission.RECORD_AUDIO
                                    ) == PackageManager.PERMISSION_GRANTED
                                ) {
                                    startVoiceRecording()
                                } else {
                                    audioPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                                }
                            },
                            onClearConversation = { showClearConversationDialog = true },
                            onDeleteChat = { showDeleteChatDialog = true },
                            listState = listState,
                            context = context
                        )
                    } else {
                        EmptyChatState(
                            onGenerateCode = {
                                chatManager.generatePairCode()
                                showGeneratePairDialog = true
                            },
                            onJoinCode = { showJoinPairDialog = true },
                            onCreateGroup = { showCreateGroupDialog = true }
                        )
                    }
                }
            }
        }
    }

    // Dialogs
    if (showGeneratePairDialog) {
        GeneratePairCodeDialog(
            chatManager = chatManager,
            pairCode = generatedPairCode,
            onDismiss = { showGeneratePairDialog = false }
        )
    }

    if (showJoinPairDialog) {
        JoinPairCodeDialog(
            chatManager = chatManager,
            onDismiss = { showJoinPairDialog = false }
        )
    }

    if (showCreateGroupDialog) {
        CreateGroupDialog(
            chatManager = chatManager,
            onDismiss = { showCreateGroupDialog = false }
        )
    }

    if (showJoinGroupDialog) {
        JoinGroupDialog(
            chatManager = chatManager,
            onDismiss = { showJoinGroupDialog = false }
        )
    }

    if (showSettingsDialog) {
        SettingsDialog(
            chatManager = chatManager,
            onDismiss = { showSettingsDialog = false },
            onLockAccount = onLockAccount
        )
    }

    if (showClearConversationDialog) {
        AlertDialog(
            onDismissRequest = { showClearConversationDialog = false },
            title = { Text("Șterge mesajele?") },
            text = { Text("Se vor șterge toate mesajele din această conversație, doar de pe acest dispozitiv.") },
            confirmButton = {
                TextButton(onClick = {
                    chatManager.clearSelectedConversation()
                    showClearConversationDialog = false
                }) { Text("Șterge") }
            },
            dismissButton = {
                TextButton(onClick = { showClearConversationDialog = false }) { Text("Anulează") }
            }
        )
    }

    if (showDeleteChatDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteChatDialog = false },
            title = { Text("Șterge chatul?") },
            text = { Text("Chatul și mesajele lui vor fi eliminate de pe acest dispozitiv. Ceilalți membri nu sunt afectați.") },
            confirmButton = {
                TextButton(onClick = {
                    chatManager.deleteSelectedChat()
                    showDeleteChatDialog = false
                }) { Text("Șterge chatul") }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteChatDialog = false }) { Text("Anulează") }
            }
        )
    }
}

@Composable
fun ChatPane(
    title: String,
    subtitle: String,
    isGroup: Boolean,
    transferProgress: String?,
    messages: List<ChatMessage>,
    textInput: String,
    onTextInputChange: (String) -> Unit,
    onSendText: () -> Unit,
    onPickFile: () -> Unit,
    isRecordingVoice: Boolean,
    onRecordVoice: () -> Unit,
    onClearConversation: () -> Unit,
    onDeleteChat: () -> Unit,
    listState: androidx.compose.foundation.lazy.LazyListState,
    context: Context
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(BgDark)
    ) {
        // Chat Header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(BgCard)
                .border(width = 0.5.dp, color = Border)
                .padding(horizontal = 14.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(36.dp)
                    .clip(CircleShape)
                    .background(AccentDark),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = if (isGroup) Icons.Default.Group else Icons.Default.Person,
                    contentDescription = null,
                    tint = Accent,
                    modifier = Modifier.size(20.dp)
                )
            }

            Spacer(modifier = Modifier.width(10.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = title,
                        fontWeight = FontWeight.Bold,
                        color = TextPrimary,
                        fontSize = 15.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Icon(
                        imageVector = Icons.Default.Lock,
                        contentDescription = "Securizat",
                        tint = Success,
                        modifier = Modifier.size(14.dp)
                    )
                }
                Text(
                    text = subtitle,
                    color = TextSecondary,
                    fontSize = 11.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            var showConversationMenu by remember { mutableStateOf(false) }
            Box {
                IconButton(onClick = { showConversationMenu = true }) {
                    Icon(Icons.Default.MoreVert, contentDescription = "Opțiuni chat", tint = TextSecondary)
                }
                DropdownMenu(
                    expanded = showConversationMenu,
                    onDismissRequest = { showConversationMenu = false }
                ) {
                    DropdownMenuItem(
                        text = { Text("Șterge mesajele") },
                        onClick = {
                            showConversationMenu = false
                            onClearConversation()
                        },
                        leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null) }
                    )
                    DropdownMenuItem(
                        text = { Text("Șterge chatul") },
                        onClick = {
                            showConversationMenu = false
                            onDeleteChat()
                        },
                        leadingIcon = { Icon(Icons.Default.Delete, contentDescription = null, tint = Danger) }
                    )
                }
            }
        }

        // Transfer Progress Banner if any
        transferProgress?.let { prog ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(BgCard)
                    .padding(horizontal = 12.dp, vertical = 6.dp)
            ) {
                Text(prog, color = Accent, fontSize = 12.sp, fontWeight = FontWeight.Medium)
                Spacer(modifier = Modifier.height(4.dp))
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth(),
                    color = Accent,
                    trackColor = Border
                )
            }
        }

        // Message List
        LazyColumn(
            state = listState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .padding(horizontal = 10.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(messages) { msg ->
                MessageBubble(msg = msg, context = context)
            }
        }

        // Bottom Chat Input Bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(BgCard)
                .border(width = 0.5.dp, color = Border)
                .padding(horizontal = 8.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = onPickFile,
                modifier = Modifier.size(40.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.AttachFile,
                    contentDescription = "Atașează fișier",
                    tint = Accent,
                    modifier = Modifier.size(22.dp)
                )
            }
            IconButton(
                onClick = onRecordVoice,
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(if (isRecordingVoice) Danger.copy(alpha = 0.18f) else BgCard)
            ) {
                Icon(
                    imageVector = if (isRecordingVoice) Icons.Default.Stop else Icons.Default.Mic,
                    contentDescription = if (isRecordingVoice) {
                        "Oprește și trimite mesajul vocal"
                    } else {
                        "Înregistrează mesaj vocal"
                    },
                    tint = if (isRecordingVoice) Danger else Accent,
                    modifier = Modifier.size(22.dp)
                )
            }

            OutlinedTextField(
                value = textInput,
                onValueChange = onTextInputChange,
                placeholder = { Text("Scrie un mesaj securizat...", color = TextSecondary, fontSize = 14.sp) },
                singleLine = true,
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Accent,
                    unfocusedBorderColor = Border,
                    focusedTextColor = TextPrimary,
                    unfocusedTextColor = TextPrimary,
                    focusedContainerColor = BgDark,
                    unfocusedContainerColor = BgDark
                ),
                shape = RoundedCornerShape(20.dp),
                modifier = Modifier.weight(1f)
            )

            Spacer(modifier = Modifier.width(6.dp))

            // Send button
            IconButton(
                onClick = onSendText,
                modifier = Modifier
                    .size(42.dp)
                    .clip(CircleShape)
                    .background(Accent)
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.Send,
                    contentDescription = "Trimite",
                    tint = BgDark,
                    modifier = Modifier.size(19.dp)
                )
            }
        }

    }
}

@Composable
fun EmptyChatState(
    onGenerateCode: () -> Unit,
    onJoinCode: () -> Unit,
    onCreateGroup: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        contentAlignment = Alignment.Center
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(0.95f),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = BgCard),
            border = androidx.compose.foundation.BorderStroke(1.dp, Border)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    imageVector = Icons.Default.Key,
                    contentDescription = null,
                    tint = Accent,
                    modifier = Modifier.size(44.dp)
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = "SecureP2PChat",
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold,
                    color = Accent
                )

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "Alege o bulă de contact de sus sau conectează-te cu un cod de asociere.",
                    color = TextSecondary,
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(18.dp))

                Button(
                    onClick = onGenerateCode,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Accent)
                ) {
                    Icon(Icons.Default.Key, contentDescription = null, tint = BgDark)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Generează Cod Chat (1-la-1)", color = BgDark, fontWeight = FontWeight.Bold)
                }

                Spacer(modifier = Modifier.height(10.dp))

                OutlinedButton(
                    onClick = onJoinCode,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Accent),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Accent)
                ) {
                    Icon(Icons.Default.QrCode, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Intră cu Cod de la un Peer")
                }

                Spacer(modifier = Modifier.height(10.dp))

                OutlinedButton(
                    onClick = onCreateGroup,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary),
                    border = androidx.compose.foundation.BorderStroke(1.dp, Border)
                ) {
                    Icon(Icons.Default.GroupAdd, contentDescription = null, tint = Accent)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Creează Grup Nou")
                }
            }
        }
    }
}

@Composable
fun PeerBubbleItem(
    displayName: String,
    isOnline: Boolean,
    isSelected: Boolean,
    isGroup: Boolean,
    onClick: () -> Unit
) {
    val initials = displayName.trim().take(2).uppercase()

    Column(
        modifier = Modifier
            .width(62.dp)
            .clickable { onClick() }
            .padding(vertical = 2.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(46.dp)
                .clip(CircleShape)
                .background(if (isSelected) AccentDark else BgCard)
                .border(
                    width = if (isSelected) 2.dp else 1.dp,
                    color = if (isSelected) Accent else Border,
                    shape = CircleShape
                ),
            contentAlignment = Alignment.Center
        ) {
            if (isGroup) {
                Icon(
                    Icons.Default.Group,
                    contentDescription = null,
                    tint = if (isSelected) Accent else TextPrimary,
                    modifier = Modifier.size(22.dp)
                )
            } else {
                Text(
                    text = initials,
                    color = if (isSelected) Accent else TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp
                )
            }

            // Online green badge
            if (isOnline) {
                Box(
                    modifier = Modifier
                        .size(11.dp)
                        .clip(CircleShape)
                        .background(Success)
                        .border(1.5.dp, BgSecondary, CircleShape)
                        .align(Alignment.BottomEnd)
                )
            }
        }

        Spacer(modifier = Modifier.height(3.dp))

        Text(
            text = displayName,
            color = if (isSelected) Accent else TextSecondary,
            fontSize = 10.sp,
            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
fun MessageBubble(
    msg: ChatMessage,
    context: Context
) {
    val isOut = msg.direction == "out"
    val align = if (isOut) Alignment.End else Alignment.Start
    val bubbleColor = if (isOut) BubbleOut else BubbleIn
    val timeFormat = remember { SimpleDateFormat("HH:mm", Locale.getDefault()) }
    val formattedTime = timeFormat.format(Date(msg.timestamp))

    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = align
    ) {
        Box(
            modifier = Modifier
                .widthIn(max = 280.dp)
                .clip(
                    RoundedCornerShape(
                        topStart = 14.dp,
                        topEnd = 14.dp,
                        bottomStart = if (isOut) 14.dp else 2.dp,
                        bottomEnd = if (isOut) 2.dp else 14.dp
                    )
                )
                .background(bubbleColor)
                .border(width = 0.5.dp, color = Border, shape = RoundedCornerShape(14.dp))
                .padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
            Column {
                if (msg.msgType == "file") {
                    val parts = msg.content.split("|")
                    val filename = parts.getOrNull(0) ?: "fișier"
                    val filePath = parts.getOrNull(1) ?: ""
                    val sizeBytes = parts.getOrNull(2)?.toLongOrNull() ?: 0L
                    val extension = filename.substringAfterLast('.', "").lowercase(Locale.ROOT)
                    val isAudio = extension in setOf("m4a", "mp3", "wav", "aac", "ogg", "flac", "opus", "amr")
                    val sizeStr = if (sizeBytes > 1024 * 1024) {
                        "${sizeBytes / (1024 * 1024)} MB"
                    } else if (sizeBytes > 1024) {
                        "${sizeBytes / 1024} KB"
                    } else {
                        "$sizeBytes B"
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.InsertDriveFile,
                            contentDescription = null,
                            tint = Accent,
                            modifier = Modifier.size(28.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = filename,
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = sizeStr,
                                color = TextSecondary,
                                fontSize = 11.sp
                            )
                        }
                    }

                    if (filePath.isNotEmpty() && File(filePath).exists()) {
                        Spacer(modifier = Modifier.height(6.dp))
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(6.dp))
                                .background(Accent.copy(alpha = 0.2f))
                                .clickable {
                                    try {
                                        val f = File(filePath)
                                        val uri = FileProvider.getUriForFile(
                                            context,
                                            "${context.packageName}.fileprovider",
                                            f
                                        )
                                        val mimeType = MimeTypeMap.getSingleton()
                                            .getMimeTypeFromExtension(extension)
                                            ?: if (isAudio) "audio/*" else "*/*"
                                        val intent = Intent(Intent.ACTION_VIEW).apply {
                                            setDataAndType(uri, mimeType)
                                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                                        }
                                        context.startActivity(
                                            Intent.createChooser(
                                                intent,
                                                if (isAudio) "Redă mesajul vocal" else "Deschide atașamentul"
                                            )
                                        )
                                    } catch (e: Exception) {
                                        Toast.makeText(
                                            context,
                                            "Nu există o aplicație compatibilă pentru acest fișier",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    }
                                }
                                .padding(horizontal = 8.dp, vertical = 4.dp)
                        ) {
                            Text(
                                text = if (isAudio) "Redă audio" else "Deschide fișier",
                                color = Accent,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                } else {
                    Text(
                        text = msg.content,
                        color = TextPrimary,
                        fontSize = 14.sp
                    )
                }

                Spacer(modifier = Modifier.height(4.dp))

                Row(
                    modifier = Modifier.align(Alignment.End),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = formattedTime,
                        color = TextSecondary.copy(alpha = 0.8f),
                        fontSize = 10.sp
                    )
                    if (isOut && msg.status == "pending") {
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("în curs", color = Warning, fontSize = 10.sp)
                    } else if (isOut && msg.status == "failed") {
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("eșuat", color = Danger, fontSize = 10.sp)
                    } else if (isOut) {
                        Spacer(modifier = Modifier.width(3.dp))
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = "Trimis",
                            tint = Success,
                            modifier = Modifier.size(10.dp)
                        )
                    }
                }
            }
        }
    }
}
