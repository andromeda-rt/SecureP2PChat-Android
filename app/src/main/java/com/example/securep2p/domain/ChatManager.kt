package com.example.securep2p.domain

import android.content.Context
import android.os.SystemClock
import android.util.Log
import com.example.securep2p.crypto.CryptoEngine
import com.example.securep2p.crypto.ForwardSecrecyChain
import com.example.securep2p.crypto.GroupSenderKeyChain
import com.example.securep2p.crypto.IdentityTrust
import com.example.securep2p.data.AppSettings
import com.example.securep2p.data.ChatMessage
import com.example.securep2p.data.Contact
import com.example.securep2p.data.GroupChat
import com.example.securep2p.data.IdentityManager
import com.example.securep2p.data.StorageManager
import com.example.securep2p.data.SignalingClient
import com.example.securep2p.protocol.Constants
import com.example.securep2p.protocol.PairCode
import com.example.securep2p.protocol.Protocol
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.ceil

class ChatManager(
    private val context: Context,
    val identityManager: IdentityManager,
    val storageManager: StorageManager
) {
    companion object {
        private const val TAG = "ChatManager"
        private const val HELLO_RATE_LIMIT_MS = 8_000L
    }

    private fun setSessionKey(deviceId: String, sessionKey: ByteArray) {
        synchronized(forwardSecrecyChainsLock) {
            val existing = forwardSecrecyChains[deviceId]
            if (existing != null && existing.sessionKey.contentEquals(sessionKey)) {
                storageManager.setSessionKey(deviceId, sessionKey)
                return
            }

            val localId = identityManager.deviceId ?: error("Local identity is unavailable")
            val masterKey = identityManager.masterKey ?: error("Identity is locked")
            val storedState = storageManager.loadForwardSecrecyState(localId, deviceId, masterKey)
            val chain = if (storedState == null) {
                ForwardSecrecyChain(sessionKey, localId, deviceId).also {
                    storageManager.saveForwardSecrecyState(
                        localId,
                        deviceId,
                        masterKey,
                        it.exportState()
                    )
                }
            } else {
                ForwardSecrecyChain.importState(sessionKey, localId, deviceId, storedState)
            }

            existing?.chain?.destroy()
            existing?.sessionKey?.fill(0)
            storageManager.setSessionKey(deviceId, sessionKey)
            forwardSecrecyChains[deviceId] =
                DirectForwardSecrecyState(sessionKey.copyOf(), chain)
        }
    }

    private fun getForwardSecrecyChain(deviceId: String, sessionKey: ByteArray): ForwardSecrecyChain {
        val existing = forwardSecrecyChains[deviceId]
        if (existing != null && existing.sessionKey.contentEquals(sessionKey)) {
            return existing.chain
        }
        setSessionKey(deviceId, sessionKey)
        return synchronized(forwardSecrecyChainsLock) {
            forwardSecrecyChains[deviceId]?.chain
                ?: error("FS2 chain initialization failed")
        }
    }

    private fun <T> withForwardSecrecyChain(
        deviceId: String,
        sessionKey: ByteArray,
        operation: (ForwardSecrecyChain) -> T
    ): T = synchronized(forwardSecrecyChainsLock) {
        val chain = getForwardSecrecyChain(deviceId, sessionKey)
        val previousState = chain.exportState()
        try {
            val result = operation(chain)
            val masterKey = identityManager.masterKey ?: error("Identity is locked")
            storageManager.saveForwardSecrecyState(
                identityManager.deviceId ?: error("Local identity is unavailable"),
                deviceId,
                masterKey,
                chain.exportState()
            )
            result
        } catch (e: Exception) {
            val localId = identityManager.deviceId ?: error("Local identity is unavailable")
            val restored = ForwardSecrecyChain.importState(
                sessionKey,
                localId,
                deviceId,
                previousState
            )
            chain.destroy()
            forwardSecrecyChains[deviceId]?.sessionKey?.fill(0)
            forwardSecrecyChains[deviceId] =
                DirectForwardSecrecyState(sessionKey.copyOf(), restored)
            throw e
        }
    }

    private fun encryptDirectMessage(
        deviceId: String,
        sessionKey: ByteArray,
        plaintext: ByteArray
    ): ByteArray = withForwardSecrecyChain(deviceId, sessionKey) { it.encrypt(plaintext) }

    private fun decryptDirectMessage(
        deviceId: String,
        sessionKey: ByteArray,
        payload: ByteArray
    ): ByteArray {
        require(ForwardSecrecyChain.isPayload(payload)) {
            "Protocol criptografic vechi/neacceptat; re-asociați contactul"
        }
        return withForwardSecrecyChain(deviceId, sessionKey) { it.decrypt(payload) }
    }

    private fun removeForwardSecrecyState(deviceId: String) {
        synchronized(forwardSecrecyChainsLock) {
            forwardSecrecyChains.remove(deviceId)?.let {
                it.chain.destroy()
                it.sessionKey.fill(0)
            }
        }
    }

    private val scope = CoroutineScope(Dispatchers.IO + Job())
    private val helloSentAt = mutableMapOf<String, Long>()
    private val helloSentAtLock = Any()
    private val forwardSecrecyChains = mutableMapOf<String, DirectForwardSecrecyState>()
    private val forwardSecrecyChainsLock = Any()
    private val signalingLifecycleMutex = Mutex()
    private var signalingClient: SignalingClient? = null

    private var heartbeatJob: Job? = null
    private var relayPollJob: Job? = null
    private var pairWatchJob: Job? = null
    private var transferProgressClearJob: Job? = null
    private val transferProgressGeneration = AtomicLong()

    private val _activePeers = MutableStateFlow<List<Contact>>(emptyList())
    val activePeers: StateFlow<List<Contact>> = _activePeers.asStateFlow()

    private val _activeGroups = MutableStateFlow<List<GroupChat>>(emptyList())
    val activeGroups: StateFlow<List<GroupChat>> = _activeGroups.asStateFlow()

    private val _selectedPeerId = MutableStateFlow<String?>(null)
    val selectedPeerId: StateFlow<String?> = _selectedPeerId.asStateFlow()

    private val _currentMessages = MutableStateFlow<List<ChatMessage>>(emptyList())
    val currentMessages: StateFlow<List<ChatMessage>> = _currentMessages.asStateFlow()

    private val _connectionState = MutableStateFlow("Deconectat")
    val connectionState: StateFlow<String> = _connectionState.asStateFlow()

    private val _generatedPairCode = MutableStateFlow<String?>(null)
    val generatedPairCode: StateFlow<String?> = _generatedPairCode.asStateFlow()

    private val _statusNotification = MutableStateFlow<String?>(null)
    val statusNotification: StateFlow<String?> = _statusNotification.asStateFlow()

    private val _transferProgress = MutableStateFlow<String?>(null)
    val transferProgress: StateFlow<String?> = _transferProgress.asStateFlow()

    private class IncomingFile(
        val transferId: String,
        val filename: String,
        val fileSize: Long,
        val totalChunks: Int,
        val fromId: String,
        val conversationId: String = fromId
    ) {
        val chunks = mutableMapOf<Int, ByteArray>()
    }

    private val incomingFiles = mutableMapOf<String, IncomingFile>()
    private val pendingGroupTexts = mutableMapOf<String, MutableList<String>>()
    private val pendingGroupTextsLock = Any()
    private val pendingGroupFrames = mutableMapOf<String, MutableList<PendingGroupFrame>>()
    private val pendingGroupFramesLock = Any()
    private val groupEpochRequestJobs = mutableMapOf<String, Job>()
    private val groupEpochRequestJobsLock = Any()
    private data class PendingGroupFrame(val groupId: String, val frame: ByteArray)
    private data class PendingIncomingGroupFrame(
        val fromId: String,
        val groupId: String,
        val epoch: Long,
        val encryptedFrame: ByteArray
    )
    private val pendingIncomingGroupFrames = mutableListOf<PendingIncomingGroupFrame>()
    private val pendingIncomingGroupFramesLock = Any()
    private val pendingRelayInbox = PendingRelayInbox()
    private val pendingSendMutexes = mutableMapOf<String, Mutex>()
    private val pendingSendMutexesLock = Any()
    private data class DirectForwardSecrecyState(
        val sessionKey: ByteArray,
        val chain: ForwardSecrecyChain
    )

    private val filesDir: File by lazy {
        File(context.filesDir, "transfers").apply { mkdirs() }
    }

    init {
        refreshContactsAndGroups()
    }

    fun refreshContactsAndGroups() {
        _activePeers.value = storageManager.getContacts()
        _activeGroups.value = storageManager.getGroups()
        _selectedPeerId.value?.let { refreshMessagesFor(it) }
    }

    fun selectPeer(deviceId: String?) {
        _selectedPeerId.value = deviceId
        if (deviceId != null) {
            refreshMessagesFor(deviceId)
        } else {
            _currentMessages.value = emptyList()
        }
    }

    fun clearSelectedConversation() {
        val selectedId = _selectedPeerId.value ?: return
        storageManager.clearMessages(selectedId)
        refreshMessagesFor(selectedId)
        showToast("Conversație ștearsă")
    }

    fun deleteSelectedChat() {
        val selectedId = _selectedPeerId.value ?: return
        storageManager.removeChat(selectedId)
        removeForwardSecrecyState(selectedId)
        pendingRelayInbox.remove(selectedId)
        synchronized(pendingGroupFramesLock) {
            pendingGroupFrames.remove(selectedId)
            pendingGroupFrames.values.forEach { frames ->
                frames.removeAll { it.groupId == selectedId }
            }
        }
        synchronized(pendingGroupTextsLock) { pendingGroupTexts.remove(selectedId) }
        refreshContactsAndGroups()
        selectPeer(null)
        showToast("Chat șters de pe acest dispozitiv")
    }

    private fun refreshMessagesFor(contactId: String) {
        _currentMessages.value = storageManager.getMessages(contactId)
    }

    fun showToast(msg: String) {
        _statusNotification.value = msg
        scope.launch {
            delay(3500)
            if (_statusNotification.value == msg) {
                _statusNotification.value = null
            }
        }
    }

    private fun setTransferProgress(message: String, clearAfterMs: Long? = null) {
        val generation = transferProgressGeneration.incrementAndGet()
        transferProgressClearJob?.cancel()
        _transferProgress.value = message
        transferProgressClearJob = clearAfterMs?.let { timeout ->
            scope.launch {
                delay(timeout)
                if (transferProgressGeneration.get() == generation) {
                    _transferProgress.value = null
                    transferProgressClearJob = null
                }
            }
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun start() {
        if (!identityManager.isUnlocked()) return
        val settings = storageManager.loadSettings()
        val client = SignalingClient(
            context = context,
            host = settings.signalHost,
            port = settings.signalPort,
            useTls = settings.useTls,
            useTor = settings.useTor,
            torSocksHost = settings.torSocksHost,
            torSocksPort = settings.torSocksPort
        )

        val x25519 = identityManager.x25519KeyPair!!
        val ed25519 = identityManager.ed25519KeyPair!!
        client.setIdentity(
            deviceId = identityManager.deviceId!!,
            signingPrivateKey = ed25519.privateKey,
            verifyKeyBytes = ed25519.verifyKey,
            publicKeyBytes = x25519.publicKey,
            displayName = identityManager.displayName ?: "Android"
        )
        this.signalingClient = client

        heartbeatJob?.cancel()
        relayPollJob?.cancel()
        pairWatchJob?.cancel()

        scope.launch {
            connectAndRegister()
            startHeartbeatLoop()
            startRelayPollLoop()
        }
    }

    fun stop() {
        heartbeatJob?.cancel()
        relayPollJob?.cancel()
        pairWatchJob?.cancel()
        scope.launch {
            signalingClient?.close()
            _connectionState.value = "Deconectat"
        }
    }

    fun updateSettingsAndReconnect(settings: AppSettings) {
        storageManager.saveSettings(settings)
        stop()
        start()
    }

    private suspend fun connectAndRegister() {
        signalingLifecycleMutex.withLock {
            val client = signalingClient ?: return
            if (client.isConnected && _connectionState.value == "Conectat la Releu") return

            val wasConnected = client.isConnected
            _connectionState.value = if (wasConnected) "Reînregistrare..." else "Reconectare..."

            if (!wasConnected && !client.connect()) {
                _connectionState.value = "Deconectat"
                val err = client.lastError.ifEmpty { "Eroare rețea" }
                showToast("Conexiune eșuată: $err")
                return
            }

            if (client.register()) {
                _connectionState.value = "Conectat la Releu"
                if (!wasConnected) {
                    showToast("Conectat la releul de semnalizare")
                }
                rehelloAllContacts()
            } else {
                _connectionState.value = "Eroare înregistrare"
                val reason = client.lastError.ifEmpty { "serverul a refuzat cererea" }
                showToast("Înregistrarea pe releu a eșuat: $reason")
            }
        }
    }

    private suspend fun rehelloAllContacts() {
        val client = signalingClient ?: return
        val contacts = storageManager.getContacts()
        for (c in contacts) {
            sendHello(c.deviceId)
        }
    }

    private fun startHeartbeatLoop() {
        heartbeatJob = scope.launch {
            var failures = 0
            while (isActive) {
                delay(Constants.SIGNAL_HEARTBEAT_SECONDS * 1000)
                val client = signalingClient ?: continue
                if (client.isConnected) {
                    if (client.heartbeat()) {
                        failures = 0
                    } else {
                        failures++
                        if (!client.isConnected || failures >= 3) {
                            connectAndRegister()
                            failures = 0
                        }
                    }
                } else {
                    connectAndRegister()
                    failures = 0
                }
            }
        }
    }

    private fun startRelayPollLoop() {
        relayPollJob = scope.launch {
            var failCount = 0
            while (isActive) {
                delay(Constants.RELAY_POLL_INTERVAL_MS)
                val client = signalingClient ?: continue
                if (!client.isConnected) {
                    continue
                }
                val messages = client.relayPoll()
                if (messages == null) {
                    failCount++
                    if (failCount >= 3) {
                        Log.w(TAG, "Relay poll failed 3 times, reconnecting...")
                        _connectionState.value = "Reconectare..."
                        connectAndRegister()
                        failCount = 0
                    }
                } else {
                    failCount = 0
                    val acknowledgedIds = mutableListOf<String>()
                    for (msg in messages) {
                        try {
                            handleRelayPayload(msg.from, msg.payload)
                            if (msg.id.isNotBlank()) acknowledgedIds.add(msg.id)
                        } catch (e: Exception) {
                            Log.e(TAG, "Error handling payload from ${msg.from}: ${e.message}")
                        }
                    }
                    if (acknowledgedIds.isNotEmpty() && !client.relayAck(acknowledgedIds)) {
                        Log.w(TAG, "Relay messages remain queued because acknowledgment failed")
                    }
                }
            }
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun handleRelayPayload(fromId: String, raw: ByteArray) {
        if (fromId.isBlank() || fromId == identityManager.deviceId) return
        if (raw.isEmpty()) return
        val msgType = raw[0]
        val payload = raw.copyOfRange(1, raw.size)

        // 0xFE: Server notify that a peer joined our pair code
        if (msgType == Constants.MSG_PAIR_JOINED_NOTIFY) {
            handlePairJoinedNotify(fromId, payload)
            return
        }

        if (msgType == Constants.MSG_HELLO || msgType == Constants.MSG_HELLO_ACK) {
            handleHello(fromId, payload, isHello = (msgType == Constants.MSG_HELLO))
            return
        }

        val requiresPairwiseSession = msgType in listOf(
            Constants.MSG_TEXT,
            Constants.MSG_FILE_START,
            Constants.MSG_FILE_CHUNK,
            Constants.MSG_FILE_END,
            Constants.MSG_GROUP_TEXT,
            Constants.MSG_GROUP_META
        )

        if (requiresPairwiseSession) {
            if (storageManager.isContactHidden(fromId) &&
                msgType != Constants.MSG_GROUP_TEXT &&
                msgType != Constants.MSG_GROUP_META
            ) return
            var sk = storageManager.getSessionKey(fromId)
            var contact = storageManager.getContact(fromId)
            if (sk == null && contact != null && contact.publicKey.isNotEmpty()) {
                try {
                    val peerPub = contact.publicKey.hexToByteArray()
                    val myPriv = identityManager.x25519KeyPair!!.privateKey
                    sk = CryptoEngine.performKeyExchange(myPriv, peerPub)
                    setSessionKey(fromId, sk)
                    flushPendingRelayInbox(fromId)
                    flushPendingOutgoingMessages(fromId)
                } catch (e: Exception) {
                    Log.e(TAG, "Rebuild session key failed: ${e.message}")
                }
            }

            if (sk == null) {
                if (contact == null) {
                    contact = Contact(
                        deviceId = fromId,
                        displayName = "Peer-${fromId.take(8)}"
                    )
                    storageManager.addOrUpdateContact(contact)
                    refreshContactsAndGroups()
                }
                check(pendingRelayInbox.enqueue(fromId, raw)) {
                    "Pending incoming-message queue is full for $fromId"
                }
                Log.w(TAG, "Buffered incoming message (type 0x${"%02X".format(msgType)}) until HELLO establishes a session with $fromId")
                sendHello(fromId)
                return
            }
        }

        if (msgType == Constants.MSG_TEXT) {
            var contact = storageManager.getContact(fromId)
            val sk = storageManager.getSessionKey(fromId) ?: return
            try {
                val plainBytes = decryptDirectMessage(fromId, sk, payload)
                val text = String(plainBytes, Charsets.UTF_8)
                val chatMsg = ChatMessage(
                    contactId = fromId,
                    direction = "in",
                    msgType = "text",
                    content = text
                )
                storageManager.addMessage(chatMsg)
                if (_selectedPeerId.value == fromId) {
                    refreshMessagesFor(fromId)
                }
                showToast("Mesaj de la ${contact?.displayName ?: fromId.take(8)}")
            } catch (e: Exception) {
                Log.e(TAG, "Decrypt text message failed: ${e.message}")
                showToast("Decriptarea a eșuat; se renegociază sesiunea securizată...")
                removeForwardSecrecyState(fromId)
                val localId = identityManager.deviceId
                if (localId != null) {
                    storageManager.clearForwardSecrecyState(localId, fromId)
                }
                storageManager.clearSessionKey(fromId)
                sendHello(fromId)
            }
            return
        }

        if (msgType == Constants.MSG_FILE_START) {
            if (storageManager.isContactHidden(fromId)) return
            try {
                val sessionKey = storageManager.getSessionKey(fromId) ?: return
                val startData = Protocol.parseFileStart(
                    decryptDirectMessage(fromId, sessionKey, payload)
                )
                require(startData.fileSize in 0..Constants.MAX_FILE_SIZE.toLong())
                require(startData.totalChunks > 0)
                require(
                    startData.filename.isNotBlank() &&
                        startData.filename != "." &&
                        startData.filename != ".." &&
                        '/' !in startData.filename &&
                        '\\' !in startData.filename
                )
                require(incomingFiles[startData.transferId] == null)
                incomingFiles[startData.transferId] = IncomingFile(
                    transferId = startData.transferId,
                    filename = startData.filename,
                    fileSize = startData.fileSize,
                    totalChunks = startData.totalChunks,
                    fromId = fromId
                )
                setTransferProgress("Se primește ${startData.filename}...")
            } catch (e: Exception) {
                Log.e(TAG, "Parse FILE_START failed: ${e.message}")
            }
            return
        }

        if (msgType == Constants.MSG_FILE_CHUNK) {
            try {
                val chunkData = Protocol.parseFileChunk(payload)
                val fileState = incomingFiles[chunkData.transferId] ?: return
                require(fileState.fromId == fromId)
                if (chunkData.chunkIndex !in 0 until fileState.totalChunks) {
                    throw IllegalArgumentException("Invalid file chunk index")
                }
                val chunk = decryptDirectMessage(
                    fileState.fromId,
                    storageManager.getSessionKey(fileState.fromId) ?: return,
                    chunkData.encryptedData
                )
                val expectedSize = minOf(
                    Constants.FILE_CHUNK_SIZE.toLong(),
                    fileState.fileSize - chunkData.chunkIndex.toLong() * Constants.FILE_CHUNK_SIZE
                ).toInt()
                require(chunk.size == expectedSize)
                fileState.chunks[chunkData.chunkIndex] = chunk
                val percent = (fileState.chunks.size * 100) / fileState.totalChunks
                setTransferProgress("Se primește ${fileState.filename} ($percent%)...")
            } catch (e: Exception) {
                Log.e(TAG, "Parse FILE_CHUNK failed: ${e.message}")
            }
            return
        }

        if (msgType == Constants.MSG_FILE_END) {
            try {
                val tid = Protocol.parseFileEnd(
                    decryptDirectMessage(
                        fromId,
                        storageManager.getSessionKey(fromId) ?: return,
                        payload
                    )
                )
                val fileState = incomingFiles[tid] ?: return
                require(fileState.fromId == fromId)
                if (fileState.chunks.size != fileState.totalChunks) {
                    incomingFiles.remove(tid)
                    setTransferProgress("Eroare: fișier incomplet", clearAfterMs = 5000)
                    return
                }
                if (fileState.chunks.values.sumOf { it.size.toLong() } != fileState.fileSize) {
                    incomingFiles.remove(tid)
                    throw IllegalArgumentException("Invalid received file size")
                }

                val destFile = File(filesDir, fileState.filename)
                destFile.outputStream().use { fos ->
                    for (i in 0 until fileState.totalChunks) {
                        fos.write(fileState.chunks[i] ?: error("Missing file chunk $i"))
                    }
                }
                incomingFiles.remove(tid)

                val chatMsg = ChatMessage(
                    contactId = fileState.fromId,
                    direction = "in",
                    msgType = "file",
                    content = "${fileState.filename}|${destFile.absolutePath}|${fileState.fileSize}"
                )
                storageManager.addMessage(chatMsg)
                if (_selectedPeerId.value == fileState.fromId) {
                    refreshMessagesFor(fileState.fromId)
                }
                setTransferProgress("✓ Primit: ${fileState.filename}", clearAfterMs = 5000)
                showToast("Fișier primit: ${fileState.filename}")
            } catch (e: Exception) {
                Log.e(TAG, "Parse FILE_END failed: ${e.message}")
                setTransferProgress("Eroare la primirea fișierului", clearAfterMs = 5000)
            }
            return
        }

        if (msgType == Constants.MSG_GROUP_TEXT) {
            handleGroupTextMessage(fromId, payload)
            return
        }
        if (msgType == Constants.MSG_GROUP_META) {
            handleGroupMetaMessage(fromId, payload)
            return
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun flushPendingRelayInbox(peerId: String) {
        val pending = pendingRelayInbox.takeAll(peerId)
        for (index in pending.indices) {
            if (storageManager.getSessionKey(peerId) == null) {
                pendingRelayInbox.restoreFirst(peerId, pending.drop(index))
                return
            }
            try {
                handleRelayPayload(peerId, pending[index])
            } catch (e: Exception) {
                pendingRelayInbox.restoreFirst(peerId, pending.drop(index))
                throw e
            }
        }
    }

    private fun pendingSendMutex(peerId: String): Mutex =
        synchronized(pendingSendMutexesLock) {
            pendingSendMutexes.getOrPut(peerId) { Mutex() }
        }

    private suspend fun flushPendingOutgoingMessages(peerId: String) {
        pendingSendMutex(peerId).withLock {
            val client = signalingClient ?: return@withLock
            if (!client.isConnected) return@withLock
            val sessionKey = storageManager.getSessionKey(peerId) ?: return@withLock
            for (message in storageManager.getPendingOutgoingTextMessages(peerId)) {
                try {
                    val encrypted = encryptDirectMessage(
                        peerId,
                        sessionKey,
                        message.content.toByteArray(Charsets.UTF_8)
                    )
                    val wirePayload = byteArrayOf(Constants.MSG_TEXT) + encrypted
                    if (!client.relaySend(peerId, wirePayload)) {
                        Log.w(TAG, "Queued text remains pending for $peerId")
                        return@withLock
                    }
                    storageManager.updateMessageStatus(message.id, "sent")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to flush queued text for $peerId: ${e.message}")
                    return@withLock
                }
            }
            if (_selectedPeerId.value == peerId) refreshMessagesFor(peerId)
        }
    }

    private suspend fun handlePairJoinedNotify(fromId: String, payload: ByteArray) {
        try {
            val json = JSONObject(String(payload, Charsets.UTF_8))
            val peerId = json.optString("device_id", json.optString("peer_id", fromId))
            val name = json.optString("display_name").trim().ifEmpty { "Peer-${peerId.take(8)}" }
            val pub = json.optString("public_key")
            val vk = json.optString("verify_key")
            val peerPublicKey = pub.hexToByteArray()
            val verifyKey = vk.hexToByteArray()
            require(peerId.isNotBlank() && peerPublicKey.size == 32 && verifyKey.size == 32) {
                "Peer identity keys are missing or malformed"
            }
            val fp = CryptoEngine.publicKeyFingerprint(verifyKey)
            var contact = storageManager.getContact(peerId)
            if (contact != null && !IdentityTrust.fingerprintTransitionAllowed(
                    contact.fingerprint, contact.publicKey, fp, pub
                )
            ) {
                showToast("Cheia de identitate a contactului s-a schimbat; asocierea a fost refuzată")
                return
            }

            storageManager.restoreContact(peerId)
            if (contact == null) {
                contact = Contact(
                    deviceId = peerId,
                    displayName = name,
                    publicKey = pub,
                    fingerprint = fp,
                    isOnline = true
                )
            } else {
                contact.displayName = name
                if (pub.isNotEmpty()) contact.publicKey = pub
                if (fp.isNotEmpty()) contact.fingerprint = fp
                contact.isOnline = true
            }
            storageManager.addOrUpdateContact(contact)

            val myPriv = identityManager.x25519KeyPair!!.privateKey
            val sk = CryptoEngine.performKeyExchange(myPriv, peerPublicKey)
            setSessionKey(peerId, sk)
            flushPendingRelayInbox(peerId)
            flushPendingOutgoingMessages(peerId)

            refreshContactsAndGroups()
            selectPeer(peerId)
            _generatedPairCode.value = null
            showToast("Peer conectat: $name")
            sendHello(peerId)
        } catch (e: Exception) {
            Log.e(TAG, "handlePairJoinedNotify failed: ${e.message}")
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun handleHello(fromId: String, payload: ByteArray, isHello: Boolean) {
        try {
            if (!Protocol.verifyKeyExchange(payload)) {
                Log.w(TAG, "HELLO verification failed from $fromId")
                return
            }
            val kex = Protocol.parseKeyExchange(payload)
            if (kex.deviceId != fromId) {
                Log.w(TAG, "Sender deviceId mismatch: ${kex.deviceId} vs $fromId")
                return
            }

            val peerFp = CryptoEngine.publicKeyFingerprint(kex.verifyKey)
            val isHidden = storageManager.isContactHidden(fromId)
            var contact = storageManager.getContact(fromId)
            if (contact != null && !IdentityTrust.fingerprintTransitionAllowed(
                    contact.fingerprint,
                    contact.publicKey,
                    peerFp,
                    kex.publicKey.toHexString()
                )
            ) {
                Log.w(TAG, "Identity key changed for $fromId; HELLO rejected")
                showToast("Atenție: cheia de identitate a contactului s-a schimbat")
                return
            }
            val name = contact?.displayName ?: "Peer-${fromId.take(8)}"

            if (!isHidden) {
                if (contact == null) {
                    contact = Contact(
                        deviceId = fromId,
                        displayName = name,
                        publicKey = kex.publicKey.toHexString(),
                        fingerprint = peerFp,
                        isOnline = true
                    )
                } else {
                    contact.publicKey = kex.publicKey.toHexString()
                    contact.fingerprint = peerFp
                    contact.isOnline = true
                }
                storageManager.addOrUpdateContact(contact)
            }

            val myPriv = identityManager.x25519KeyPair!!.privateKey
            val isNewSecureChannel = storageManager.getSessionKey(fromId) == null
            val sk = CryptoEngine.performKeyExchange(myPriv, kex.publicKey)
            setSessionKey(fromId, sk)
            flushPendingRelayInbox(fromId)
            flushPendingOutgoingMessages(fromId)
            flushPendingGroupFrames(fromId)
            syncCreatorGroupKeysToPeer(fromId)
            requestGroupEpochsFromPeer(fromId)

            refreshContactsAndGroups()
            if (!isHidden && _selectedPeerId.value == null) {
                selectPeer(fromId)
            }

            if (isHello) {
                val client = signalingClient ?: return
                val myPub = identityManager.x25519KeyPair!!.publicKey
                val mySignPriv = identityManager.ed25519KeyPair!!.privateKey
                val mySignPub = identityManager.ed25519KeyPair!!.verifyKey
                val ackBytes = Protocol.createKeyExchange(
                    publicKey = myPub,
                    deviceId = identityManager.deviceId!!,
                    displayName = "",
                    signingPrivateKey = mySignPriv,
                    verifyKey = mySignPub
                )
                val wireAck = ByteArray(1 + ackBytes.size)
                wireAck[0] = Constants.MSG_HELLO_ACK
                System.arraycopy(ackBytes, 0, wireAck, 1, ackBytes.size)
                client.relaySend(fromId, wireAck)
            }

            if (isNewSecureChannel) {
                showToast("Canal securizat cu $name")
            }
        } catch (e: Exception) {
            Log.e(TAG, "handleHello error: ${e.message}")
        }
    }

    suspend fun sendHello(toDeviceId: String) {
        val targetId = toDeviceId.trim()
        if (targetId.isEmpty() || targetId == identityManager.deviceId) return
        val client = signalingClient ?: return
        if (!client.isConnected) return
        val now = SystemClock.elapsedRealtime()
        synchronized(helloSentAtLock) {
            val lastSentAt = helloSentAt[targetId]
            if (lastSentAt != null && now - lastSentAt < HELLO_RATE_LIMIT_MS) return
            helloSentAt.entries.removeAll { now - it.value >= HELLO_RATE_LIMIT_MS }
            helloSentAt[targetId] = now
        }
        val myPub = identityManager.x25519KeyPair!!.publicKey
        val mySignPriv = identityManager.ed25519KeyPair!!.privateKey
        val mySignPub = identityManager.ed25519KeyPair!!.verifyKey

        val kexBytes = Protocol.createKeyExchange(
            publicKey = myPub,
            deviceId = identityManager.deviceId!!,
            displayName = "",
            signingPrivateKey = mySignPriv,
            verifyKey = mySignPub
        )

        val wireHello = ByteArray(1 + kexBytes.size)
        wireHello[0] = Constants.MSG_HELLO
        System.arraycopy(kexBytes, 0, wireHello, 1, kexBytes.size)
        client.relaySend(targetId, wireHello)
    }

    // --- User Actions ---
    @OptIn(ExperimentalStdlibApi::class)
    fun sendTextMessage(text: String) {
        val toId = _selectedPeerId.value ?: return
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return
        if (storageManager.getGroup(toId) != null) {
            sendGroupTextMessage(toId, trimmed)
            return
        }

        val sk = storageManager.getSessionKey(toId)
        val outMsg = ChatMessage(
            contactId = toId,
            direction = "out",
            msgType = "text",
            content = trimmed,
            status = "pending"
        )
        storageManager.addMessage(outMsg)
        refreshMessagesFor(toId)

        scope.launch {
            if (sk == null) {
                showToast("Se inițializează cheia cu contactul...")
                sendHello(toId)
                return@launch
            }
            flushPendingOutgoingMessages(toId)
        }
    }

    private fun sendGroupTextMessage(groupId: String, text: String) {
        val group = storageManager.getGroup(groupId) ?: return
        storageManager.addMessage(
            ChatMessage(
                contactId = groupId,
                direction = "out",
                msgType = "text",
                content = text
            )
        )
        refreshMessagesFor(groupId)

        scope.launch { sendGroupTextFrame(groupId, text) }
    }

    private suspend fun sendGroupTextFrame(groupId: String, text: String) {
        val group = storageManager.getGroup(groupId) ?: return
        val client = signalingClient
        if (client == null || !client.isConnected) {
            showToast("Releul nu este conectat")
            return
        }
        val info = client.groupInfo(groupId)
        if (info == null) {
            showToast("Nu s-au putut actualiza membrii grupului")
            return
        }

        val previousMembers = group.members.toSet()
        val memberIds = updateGroupMembers(group, info)
            .filter { it != identityManager.deviceId }
        if (memberIds.isEmpty()) {
            showToast("Grupul nu are alți membri încă")
            return
        }

        val secret = refreshGroupEpoch(group, previousMembers != group.members.toSet())
        if (secret == null) {
            synchronized(pendingGroupTextsLock) {
                val pending = pendingGroupTexts.getOrPut(groupId) { mutableListOf() }
                check(pending.size < 100) { "Pending group text queue is full for $groupId" }
                pending.add(text)
            }
            requestGroupEpoch(group)
            showToast("Se așteaptă cheia securizată a grupului; mesajul va fi trimis după conectare")
            return
        }
        try {
            if (group.creatorId == identityManager.deviceId) {
                distributeGroupEpoch(client, group, secret)
            }
            val inner = groupSenderChain(group, group.epoch, identityManager.deviceId!!, secret)
                .use { chain ->
                    val encrypted = chain.encrypt(
                        JSONObject().put("kind", "text").put("text", text)
                            .toString().toByteArray(Charsets.UTF_8)
                    )
                    storageManager.saveGroupSenderState(
                        group.groupId,
                        group.epoch,
                        identityManager.deviceId!!,
                        identityManager.masterKey ?: error("Identity is locked"),
                        chain.exportState()
                    )
                    encrypted
                }
            var initializingKeys = false
            for (memberId in memberIds) {
                if (storageManager.getSessionKey(memberId) == null) {
                    synchronized(pendingGroupFramesLock) {
                        val pending = pendingGroupFrames.getOrPut(memberId) { mutableListOf() }
                        check(pending.size < 100) { "Pending group message queue is full for $memberId" }
                        pending.add(PendingGroupFrame(groupId, inner.copyOf()))
                    }
                    sendHello(memberId)
                    initializingKeys = true
                } else if (!sendGroupFrameToMember(client, memberId, groupId, inner)) {
                    throw IllegalStateException("Relay rejected group text for $memberId")
                }
            }
            if (initializingKeys) {
                showToast("Se negociază cheia securizată; mesajul va fi trimis după conectare")
            }
        } finally {
            secret.fill(0)
        }
    }

    private suspend fun flushPendingGroupTexts(groupId: String) {
        val pending = synchronized(pendingGroupTextsLock) {
            pendingGroupTexts.remove(groupId)?.toList().orEmpty()
        }
        for (index in pending.indices) {
            try {
                sendGroupTextFrame(groupId, pending[index])
            } catch (e: Exception) {
                Log.e(TAG, "Failed to flush pending group text: ${e.message}")
                synchronized(pendingGroupTextsLock) {
                    pendingGroupTexts.getOrPut(groupId) { mutableListOf() }
                        .addAll(0, pending.drop(index))
                }
                return
            }
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun updateGroupMembers(group: GroupChat, info: JSONObject): List<String> {
        val members = info.optJSONArray("members") ?: return group.members.toList()
        val creatorId = info.optString("creator_id").trim()
        val memberIds = mutableListOf<String>()
        for (i in 0 until members.length()) {
            val member = members.optJSONObject(i) ?: continue
            val memberId = member.optString("device_id").trim()
            if (memberId.isEmpty()) continue
            memberIds.add(memberId)
            if (memberId != identityManager.deviceId) {
                val publicKey = member.optString("public_key")
                val existing = storageManager.getContact(memberId)
                if (existing == null && !storageManager.isContactHidden(memberId)) {
                    val contact = Contact(
                        deviceId = memberId,
                        displayName = member.optString("display_name").ifBlank { "Peer-${memberId.take(8)}" }
                    )
                    if (publicKey.isNotEmpty()) {
                        try {
                            require(publicKey.hexToByteArray().size == 32)
                            contact.publicKey = publicKey
                        } catch (e: IllegalArgumentException) {
                            Log.w(TAG, "Invalid public key for group member ${memberId.take(8)}")
                        }
                    }
                    storageManager.addOrUpdateContact(contact)
                } else if (existing != null && existing.publicKey.isEmpty() && publicKey.isNotEmpty()) {
                    try {
                        require(publicKey.hexToByteArray().size == 32)
                        existing.publicKey = publicKey
                        storageManager.addOrUpdateContact(existing)
                    } catch (e: IllegalArgumentException) {
                        Log.w(TAG, "Invalid public key for existing group member ${memberId.take(8)}")
                    }
                }
            }
        }
        group.creatorId = creatorId.ifEmpty { memberIds.firstOrNull() ?: group.creatorId }
        group.members.clear()
        group.members.addAll(memberIds.distinct())
        storageManager.addOrUpdateGroup(group)
        refreshContactsAndGroups()
        return group.members.toList()
    }

    private suspend fun sendGroupFrameToMember(
        client: SignalingClient,
        memberId: String,
        groupId: String,
        encryptedFrame: ByteArray
    ): Boolean {
        val sessionKey = storageManager.getSessionKey(memberId) ?: return false
        val groupBytes = groupId.toByteArray(Charsets.UTF_8)
        if (groupBytes.isEmpty() || groupBytes.size > 0xffff) {
            showToast("ID-ul grupului nu este valid")
            return false
        }
        val encrypted = encryptDirectMessage(memberId, sessionKey, encryptedFrame)
        val wirePayload = ByteArray(1 + 2 + groupBytes.size + encrypted.size)
        wirePayload[0] = Constants.MSG_GROUP_TEXT
        wirePayload[1] = ((groupBytes.size shr 8) and 0xff).toByte()
        wirePayload[2] = (groupBytes.size and 0xff).toByte()
        System.arraycopy(groupBytes, 0, wirePayload, 3, groupBytes.size)
        System.arraycopy(encrypted, 0, wirePayload, 3 + groupBytes.size, encrypted.size)
        val sent = client.relaySend(memberId, wirePayload)
        if (!sent) {
            showToast("Mesajul nu a putut fi trimis către ${storageManager.getContact(memberId)?.displayName ?: memberId.take(8)}")
        }
        return sent
    }

    private fun groupSenderChain(
        group: GroupChat,
        epoch: Long,
        senderId: String,
        epochSecret: ByteArray
    ): GroupSenderKeyChain {
        val masterKey = identityManager.masterKey ?: error("Identity is locked")
        val state = storageManager.loadGroupSenderState(group.groupId, epoch, senderId, masterKey)
        return if (state == null) {
            GroupSenderKeyChain(epochSecret, group.groupId, epoch, senderId)
        } else {
            GroupSenderKeyChain.importState(epochSecret, state).also {
                require(it.groupId == group.groupId && it.epoch == epoch && it.senderId == senderId) {
                    "Stored group sender state does not match its context"
                }
            }
        }
    }

    private fun refreshGroupEpoch(group: GroupChat, membershipChanged: Boolean): ByteArray? {
        val localId = identityManager.deviceId ?: error("Local identity is unavailable")
        val masterKey = identityManager.masterKey ?: error("Identity is locked")
        val creator = group.creatorId == localId
        if (creator && (group.epoch == 0L || membershipChanged ||
                    storageManager.loadGroupEpochSecret(group.groupId, group.epoch, masterKey) == null)) {
            val nextEpoch = group.epoch + 1
            val secret = ByteArray(32).also(SecureRandom()::nextBytes)
            storageManager.saveGroupEpochSecret(group.groupId, nextEpoch, masterKey, secret)
            group.epoch = nextEpoch
            storageManager.addOrUpdateGroup(group)
            return secret
        }
        if (group.epoch == 0L) return null
        return storageManager.loadGroupEpochSecret(group.groupId, group.epoch, masterKey)
    }

    private fun requestGroupEpoch(group: GroupChat) {
        val creatorId = group.creatorId
        if (creatorId.isBlank() || creatorId == identityManager.deviceId) return
        val groupId = group.groupId
        synchronized(groupEpochRequestJobsLock) {
            if (groupEpochRequestJobs[groupId]?.isActive == true) return
            lateinit var requestJob: Job
            requestJob = scope.launch(start = CoroutineStart.LAZY) {
                var retryDelayMs = 2500L
                try {
                    while (true) {
                        val currentGroup = storageManager.getGroup(groupId) ?: return@launch
                        if (currentGroup.creatorId != creatorId) return@launch
                        val masterKey = identityManager.masterKey ?: return@launch
                        if (currentGroup.epoch > 0L &&
                            storageManager.loadGroupEpochSecret(
                                groupId, currentGroup.epoch, masterKey
                            ) != null
                        ) return@launch

                        try {
                            val client = signalingClient
                            if (client?.isConnected == true) {
                                val sessionKey = storageManager.getSessionKey(creatorId)
                                if (sessionKey == null) {
                                    sendHello(creatorId)
                                } else {
                                    val request = JSONObject()
                                        .put("kind", "key_request")
                                        .put("group_id", groupId)
                                        .put("requester_id", identityManager.deviceId)
                                        .toString().toByteArray(Charsets.UTF_8)
                                    val encrypted = encryptDirectMessage(creatorId, sessionKey, request)
                                    if (!client.relaySend(
                                            creatorId,
                                            byteArrayOf(Constants.MSG_GROUP_META) + encrypted
                                        )
                                    ) {
                                        Log.w(TAG, "Relay rejected group key request for $groupId")
                                    } else {
                                        Log.d(TAG, "Requested group key for $groupId from $creatorId")
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Group key request attempt failed for $groupId", e)
                        }
                        delay(retryDelayMs)
                        retryDelayMs = minOf(retryDelayMs * 2, 30_000L)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to request group epoch for $groupId: ${e.message}")
                } finally {
                    synchronized(groupEpochRequestJobsLock) {
                        if (groupEpochRequestJobs[groupId] === requestJob) {
                            groupEpochRequestJobs.remove(groupId)
                        }
                    }
                }
            }
            groupEpochRequestJobs[groupId] = requestJob
            requestJob.start()
        }
    }

    private suspend fun distributeGroupEpoch(
        client: SignalingClient,
        group: GroupChat,
        secret: ByteArray
    ) {
        for (memberId in group.members) {
            if (memberId == identityManager.deviceId) continue
            if (!sendGroupEpochToMember(client, group, memberId, secret)) {
                Log.w(TAG, "Could not deliver group epoch ${group.epoch} to $memberId")
            }
        }
    }

    private suspend fun flushPendingGroupFrames(memberId: String) {
        val pending = synchronized(pendingGroupFramesLock) {
            pendingGroupFrames.remove(memberId)?.toList().orEmpty()
        }
        if (pending.isEmpty()) return
        val client = signalingClient
        if (client == null || !client.isConnected) {
            synchronized(pendingGroupFramesLock) {
                pendingGroupFrames.getOrPut(memberId) { mutableListOf() }.addAll(0, pending)
            }
            return
        }
        for (index in pending.indices) {
            val item = pending[index]
            try {
                val group = storageManager.getGroup(item.groupId) ?: continue
                val epoch = java.nio.ByteBuffer.wrap(item.frame, 4, 8).long
                if (group.creatorId == identityManager.deviceId) {
                    val secret = storageManager.loadGroupEpochSecret(
                        group.groupId,
                        epoch,
                        identityManager.masterKey ?: error("Identity is locked")
                    ) ?: error("Missing group epoch secret for pending message")
                    try {
                        if (!sendGroupEpochToMember(client, group, memberId, secret, epoch)) {
                            throw IllegalStateException("Relay rejected group epoch key")
                        }
                    } finally {
                        secret.fill(0)
                    }
                }
                if (!sendGroupFrameToMember(client, memberId, item.groupId, item.frame)) {
                    throw IllegalStateException("Relay rejected pending group message")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to flush group message to $memberId: ${e.message}")
                synchronized(pendingGroupFramesLock) {
                    pendingGroupFrames.getOrPut(memberId) { mutableListOf() }
                        .addAll(0, pending.drop(index))
                }
                return
            }
        }
    }

    fun sendFile(filename: String, fileBytes: ByteArray) {
        val toId = _selectedPeerId.value ?: return
        if (fileBytes.isEmpty() || fileBytes.size > Constants.MAX_FILE_SIZE) {
            showToast("Fișierul trebuie să aibă între 1 byte și 50 MB")
            return
        }
        val safeFilename = File(filename).name
            .replace("\\", "_")
            .replace("|", "_")
            .replace(Regex("[\\u0000-\\u001F]"), "_")
            .take(240)
            .ifBlank { "atasament_${System.currentTimeMillis()}" }
            .let {
                if (it == "." || it == "..") "atasament_${System.currentTimeMillis()}" else it
            }

        if (storageManager.getGroup(toId) != null) {
            sendGroupFile(toId, safeFilename, fileBytes)
            return
        }

        val sk = storageManager.getSessionKey(toId)
        if (sk == null) {
            showToast("Nu există canal securizat pentru transfer")
            return
        }

        val localCopy = File(filesDir, safeFilename)
        localCopy.writeBytes(fileBytes)

        val outMsg = ChatMessage(
            contactId = toId,
            direction = "out",
            msgType = "file",
            content = "$safeFilename|${localCopy.absolutePath}|${fileBytes.size}",
            status = "pending"
        )
        storageManager.addMessage(outMsg)
        refreshMessagesFor(toId)

        scope.launch {
            suspend fun markTransferFailed(message: String) {
                storageManager.updateMessageStatus(outMsg.id, "failed")
                refreshMessagesFor(toId)
                setTransferProgress(message, clearAfterMs = 5000)
                showToast("Trimiterea fișierului a eșuat")
            }

            val client = signalingClient
            if (client == null) {
                markTransferFailed("Releul indisponibil: $safeFilename")
                return@launch
            }
            val tid = UUID.randomUUID().toString().replace("-", "").take(16)
            val chunkSize = Constants.FILE_CHUNK_SIZE
            val totalChunks = ceil(fileBytes.size.toDouble() / chunkSize).toInt()

            setTransferProgress("Se trimite $filename...")
            val startPayload = Protocol.createFileStart(tid, safeFilename, fileBytes.size.toLong(), totalChunks)
            val encryptedStart = encryptDirectMessage(toId, sk, startPayload)
            val wireStart = ByteArray(1 + encryptedStart.size)
            wireStart[0] = Constants.MSG_FILE_START
            System.arraycopy(encryptedStart, 0, wireStart, 1, encryptedStart.size)
            if (!client.relaySend(toId, wireStart)) {
                markTransferFailed("Trimitere eșuată: releul nu a acceptat $safeFilename")
                return@launch
            }

            for (i in 0 until totalChunks) {
                val start = i * chunkSize
                val end = minOf(fileBytes.size, (i + 1) * chunkSize)
                val chunk = fileBytes.copyOfRange(start, end)
                val encryptedChunk = encryptDirectMessage(toId, sk, chunk)
                val chunkPayload = Protocol.createFileChunk(tid, i, encryptedChunk)

                val wireChunk = ByteArray(1 + chunkPayload.size)
                wireChunk[0] = Constants.MSG_FILE_CHUNK
                System.arraycopy(chunkPayload, 0, wireChunk, 1, chunkPayload.size)

                if (!client.relaySend(toId, wireChunk)) {
                    markTransferFailed("Trimitere întreruptă: $safeFilename")
                    return@launch
                }
                val percent = ((i + 1) * 100) / totalChunks
                setTransferProgress("Se trimite $safeFilename ($percent%)...")
                delay(50)
            }

            val endPayload = encryptDirectMessage(toId, sk, Protocol.createFileEnd(tid))
            val wireEnd = ByteArray(1 + endPayload.size)
            wireEnd[0] = Constants.MSG_FILE_END
            System.arraycopy(endPayload, 0, wireEnd, 1, endPayload.size)
            if (!client.relaySend(toId, wireEnd)) {
                markTransferFailed("Trimitere întreruptă: $safeFilename")
                return@launch
            }

            storageManager.updateMessageStatus(outMsg.id, "sent")
            refreshMessagesFor(toId)
            setTransferProgress("✓ Trimis: $safeFilename", clearAfterMs = 5000)
            showToast("Fișier trimis: $safeFilename")
        }
    }

    private fun sendGroupFile(groupId: String, filename: String, fileBytes: ByteArray) {
        val localCopy = File(filesDir, filename)
        localCopy.writeBytes(fileBytes)
        val outMsg = ChatMessage(
            contactId = groupId,
            direction = "out",
            msgType = "file",
            content = "$filename|${localCopy.absolutePath}|${fileBytes.size}",
            status = "pending"
        )
        storageManager.addMessage(outMsg)
        refreshMessagesFor(groupId)

        scope.launch {
            suspend fun fail(message: String) {
                storageManager.updateMessageStatus(outMsg.id, "failed")
                refreshMessagesFor(groupId)
                setTransferProgress(message, clearAfterMs = 5000)
                showToast("Trimiterea fișierului în grup a eșuat")
            }

            val client = signalingClient
            if (client == null || !client.isConnected) {
                fail("Releul indisponibil: $filename")
                return@launch
            }
            val group = storageManager.getGroup(groupId) ?: return@launch
            val info = client.groupInfo(groupId)
            if (info == null) {
                fail("Nu s-au putut actualiza membrii grupului")
                return@launch
            }
            val oldMembers = group.members.toSet()
            val members = updateGroupMembers(group, info)
                .filter { it != identityManager.deviceId }
            if (members.isEmpty()) {
                fail("Grupul nu are alți membri încă")
                return@launch
            }
            val missingSession = members.filter { storageManager.getSessionKey(it) == null }
            if (missingSession.isNotEmpty()) {
                for (memberId in missingSession) sendHello(memberId)
                fail("Canalul securizat cu toți membrii nu este încă pregătit")
                return@launch
            }

            val epochSecret = refreshGroupEpoch(group, oldMembers != group.members.toSet())
            if (epochSecret == null) {
                requestGroupEpoch(group)
                fail("Se așteaptă cheia securizată a grupului")
                return@launch
            }
            if (group.creatorId == identityManager.deviceId) {
                distributeGroupEpoch(client, group, epochSecret)
            }
            val localId = identityManager.deviceId ?: error("Local identity is unavailable")
            val chain = groupSenderChain(group, group.epoch, localId, epochSecret)
            try {
                val transferId = UUID.randomUUID().toString().replace("-", "").take(16)
                val chunkSize = Constants.FILE_CHUNK_SIZE
                val totalChunks = ceil(fileBytes.size.toDouble() / chunkSize).toInt()
                setTransferProgress("Se trimite $filename...")
                suspend fun sendEvent(event: JSONObject): Boolean {
                    val encryptedFrame = chain.encrypt(event.toString().toByteArray(Charsets.UTF_8))
                    storageManager.saveGroupSenderState(
                        groupId,
                        group.epoch,
                        localId,
                        identityManager.masterKey ?: error("Identity is locked"),
                        chain.exportState()
                    )
                    for (memberId in members) {
                        if (!sendGroupFrameToMember(client, memberId, groupId, encryptedFrame)) {
                            return false
                        }
                    }
                    return true
                }
                if (!sendEvent(JSONObject().put("kind", "file_start")
                        .put("transfer_id", transferId)
                        .put("filename", filename)
                        .put("file_size", fileBytes.size)
                        .put("total_chunks", totalChunks))) {
                    fail("Trimitere întreruptă: $filename")
                    return@launch
                }
                for (index in 0 until totalChunks) {
                    val start = index * chunkSize
                    val end = minOf(fileBytes.size, start + chunkSize)
                    val chunk = fileBytes.copyOfRange(start, end)
                    val event = JSONObject().put("kind", "file_chunk")
                        .put("transfer_id", transferId)
                        .put("chunk_index", index)
                        .put("data", org.bouncycastle.util.encoders.Base64.toBase64String(chunk))
                    if (!sendEvent(event)) {
                        fail("Trimitere întreruptă: $filename")
                        return@launch
                    }
                    setTransferProgress("Se trimite $filename (${(index + 1) * 100 / totalChunks}%)...")
                    delay(50)
                }
                if (!sendEvent(JSONObject().put("kind", "file_end").put("transfer_id", transferId))) {
                    fail("Trimitere întreruptă: $filename")
                    return@launch
                }
                storageManager.updateMessageStatus(outMsg.id, "sent")
                refreshMessagesFor(groupId)
                setTransferProgress("✓ Trimis în grup: $filename", clearAfterMs = 5000)
                showToast("Fișier trimis în grup: $filename")
            } catch (e: Exception) {
                Log.e(TAG, "Group file transfer failed: ${e.message}")
                fail("Eroare la trimiterea: $filename")
            } finally {
                chain.destroy()
                epochSecret.fill(0)
            }
        }
    }

    // --- Pairing & Groups ---
    fun generatePairCode() {
        scope.launch {
            val client = signalingClient
            if (client == null || !client.isConnected) {
                showToast("Conectează-te la releu înainte de generare")
                return@launch
            }
            val code = client.pairCreate()
            if (code != null) {
                _generatedPairCode.value = code
                showToast("Cod generat: $code")
                startPairStatusWatch(code)
            } else {
                showToast("Generarea codului a eșuat")
            }
        }
    }

    private fun startPairStatusWatch(code: String) {
        pairWatchJob?.cancel()
        pairWatchJob = scope.launch {
            var waitedSeconds = 0
            while (isActive && waitedSeconds < 300) {
                delay(3000)
                waitedSeconds += 3
                val client = signalingClient ?: break
                val resp = client.pairStatus(code)
                if (resp != null && resp.optBoolean("ok", false) && resp.optBoolean("joined", false)) {
                    val peerId = resp.optString("peer_id", resp.optString("device_id"))
                    val name = resp.optString("display_name", "Peer-${peerId.take(8)}")
                    val pub = resp.optString("public_key")
                    val vk = resp.optString("verify_key")
                    val fakePayload = JSONObject().apply {
                        put("device_id", peerId)
                        put("display_name", name)
                        put("public_key", pub)
                        put("verify_key", vk)
                    }.toString().toByteArray(Charsets.UTF_8)
                    handlePairJoinedNotify(peerId, fakePayload)
                    break
                }
            }
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun joinPairCode(code: String) {
        scope.launch {
            val normalizedCode = PairCode.normalize(code)
            if (normalizedCode == null) {
                showToast("Cod invalid: introdu cele 6 caractere afișate")
                return@launch
            }
            val client = signalingClient
            if (client == null || !client.isConnected) {
                showToast("Conectează-te la releu înainte de asociere")
                return@launch
            }
            val resp = client.pairJoin(normalizedCode)
            if (resp != null && resp.optBoolean("ok", false)) {
                val peerId = resp.optString("device_id", resp.optString("peer_id"))
                val name = resp.optString("display_name").ifEmpty { "Peer-${peerId.take(8)}" }
                val pub = resp.optString("public_key")
                val vk = resp.optString("verify_key")

                storageManager.restoreContact(peerId)
                var fp = ""
                if (vk.isNotEmpty()) {
                    try {
                        fp = CryptoEngine.publicKeyFingerprint(vk.hexToByteArray())
                    } catch (e: Exception) { /* ignore */ }
                }
                val peerPublicKey = pub.hexToByteArray()
                val verifyKey = vk.hexToByteArray()
                require(peerId.isNotBlank() && peerPublicKey.size == 32 && verifyKey.size == 32) {
                    "Peer identity keys are missing or malformed"
                }
                val contact = storageManager.getContact(peerId)
                if (contact != null && !IdentityTrust.fingerprintTransitionAllowed(
                        contact.fingerprint, contact.publicKey, fp, pub
                    )
                ) {
                    showToast("Cheia de identitate a contactului s-a schimbat; asocierea a fost refuzată")
                    return@launch
                }
                val trustedContact = contact ?: Contact(
                    deviceId = peerId,
                    displayName = name,
                    publicKey = pub,
                    fingerprint = fp,
                    isOnline = true
                )
                trustedContact.displayName = name
                trustedContact.publicKey = pub
                trustedContact.fingerprint = fp
                trustedContact.isOnline = true
                storageManager.addOrUpdateContact(trustedContact)
                storageManager.restoreContact(peerId)

                val myPriv = identityManager.x25519KeyPair!!.privateKey
                val sk = CryptoEngine.performKeyExchange(myPriv, peerPublicKey)
                setSessionKey(peerId, sk)
                flushPendingRelayInbox(peerId)
                flushPendingOutgoingMessages(peerId)

                refreshContactsAndGroups()
                selectPeer(peerId)
                showToast("Asociat cu succes cu $name")
                sendHello(peerId)
            } else {
                val reason = client.lastError.ifBlank { "releul nu a acceptat codul" }
                showToast("Asociere eșuată: $reason")
            }
        }
    }

    fun createGroup(groupName: String, onCreated: (GroupChat?) -> Unit) {
        scope.launch {
            val client = signalingClient
            if (client == null || !client.isConnected) {
                showToast("Conectează-te la releu înainte de creare grup")
                onCreated(null)
                return@launch
            }
            val resp = client.groupCreate(groupName)
            if (resp != null) {
                val gid = resp.getString("group_id")
                val inviteCode = resp.getString("invite_code")
                val name = resp.optString("name", groupName)
                val grp = GroupChat(
                    groupId = gid,
                    name = name,
                    inviteCode = inviteCode,
                    members = mutableListOf(identityManager.deviceId!!),
                    creatorId = resp.optString("creator_id", identityManager.deviceId!!)
                )
                storageManager.addOrUpdateGroup(grp)
                refreshContactsAndGroups()
                selectPeer(gid)
                showToast("Grup creat: $name (Cod: $inviteCode)")
                onCreated(grp)
            } else {
                showToast("Crearea grupului a eșuat")
                onCreated(null)
            }
        }
    }

    fun joinGroup(inviteCode: String) {
        scope.launch {
            val client = signalingClient
            if (client == null || !client.isConnected) {
                showToast("Conectează-te la releu înainte de a intra în grup")
                return@launch
            }
            val resp = client.groupJoin(inviteCode)
            if (resp != null && resp.optBoolean("ok", false)) {
                val gid = resp.optString("group_id")
                val name = resp.optString("name", "Grup-${gid.take(6)}")
                val grp = GroupChat(
                    groupId = gid,
                    name = name,
                    inviteCode = inviteCode.uppercase(),
                    members = mutableListOf(identityManager.deviceId!!)
                )
                storageManager.addOrUpdateGroup(grp)
                updateGroupMembers(grp, resp)
                requestGroupEpoch(grp)
                refreshContactsAndGroups()
                selectPeer(gid)
                showToast("Ai intrat în grupul: $name")
            } else {
                showToast("Intrarea în grup a eșuat")
            }
        }
    }

    private suspend fun handleGroupTextMessage(fromId: String, payload: ByteArray) {
        try {
            if (payload.size < 3) return
            val gidLen = ((payload[0].toInt() and 0xff) shl 8) or
                (payload[1].toInt() and 0xff)
            if (gidLen == 0 || payload.size <= 2 + gidLen) return
            val gid = String(payload, 2, gidLen, Charsets.UTF_8)
            val group = storageManager.getGroup(gid) ?: return
            if (fromId !in group.members) {
                val info = signalingClient?.groupInfo(gid) ?: return
                updateGroupMembers(group, info)
                if (fromId !in group.members) return
            }
            val sessionKey = storageManager.getSessionKey(fromId) ?: run {
                sendHello(fromId)
                return
            }
            val encryptedFrame = decryptDirectMessage(
                fromId,
                sessionKey,
                payload.copyOfRange(2 + gidLen, payload.size)
            )
            if (!GroupSenderKeyChain.isFrame(encryptedFrame)) {
                throw IllegalArgumentException("Invalid group sender-key message")
            }
            val frameEpoch = java.nio.ByteBuffer.wrap(encryptedFrame, 4, 8).long
            val masterKey = identityManager.masterKey ?: error("Identity is locked")
            val epochSecret = storageManager.loadGroupEpochSecret(gid, frameEpoch, masterKey)
                ?: run {
                    synchronized(pendingIncomingGroupFramesLock) {
                        if (pendingIncomingGroupFrames.size < 200) {
                            pendingIncomingGroupFrames.add(
                                PendingIncomingGroupFrame(fromId, gid, frameEpoch, encryptedFrame)
                            )
                        }
                    }
                    if (group.creatorId != identityManager.deviceId) requestGroupEpoch(group)
                    return
                }
            val plaintext = groupSenderChain(group, frameEpoch, fromId, epochSecret).use { chain ->
                chain.decrypt(encryptedFrame).also {
                    storageManager.saveGroupSenderState(
                        gid, frameEpoch, fromId, masterKey, chain.exportState()
                    )
                }
            }
            val message = JSONObject(String(plaintext, Charsets.UTF_8))
            when (message.getString("kind")) {
                "text" -> {
                    val senderName = storageManager.getContact(fromId)?.displayName ?: fromId.take(6)
                    storageManager.addMessage(
                        ChatMessage(
                            contactId = gid,
                            direction = "in",
                            msgType = "text",
                            content = "[$senderName]: ${message.getString("text")}"
                        )
                    )
                    if (_selectedPeerId.value == gid) refreshMessagesFor(gid)
                    showToast("Mesaj în grupul ${group.name}")
                }
                "file_start" -> handleGroupFileStart(gid, fromId, message)
                "file_chunk" -> handleGroupFileChunk(gid, fromId, message)
                "file_end" -> handleGroupFileEnd(gid, fromId, message)
                else -> throw IllegalArgumentException("Unsupported group message kind")
            }
        } catch (e: Exception) {
            Log.e(TAG, "handleGroupTextMessage error: ${e.message}")
        }
    }

    private fun handleGroupFileStart(groupId: String, fromId: String, message: JSONObject) {
        val transferId = message.getString("transfer_id")
        val filename = File(message.getString("filename")).name
        val fileSize = message.getLong("file_size")
        val totalChunks = message.getInt("total_chunks")
        require(fileSize in 1..Constants.MAX_FILE_SIZE.toLong())
        require(totalChunks > 0 && filename.isNotBlank())
        require(incomingFiles[transferId] == null) { "Duplicate group file transfer ID" }
        incomingFiles[transferId] = IncomingFile(
            transferId, filename, fileSize, totalChunks, fromId, groupId
        )
        setTransferProgress("Se primește $filename...")
    }

    private fun handleGroupFileChunk(groupId: String, fromId: String, message: JSONObject) {
        val transferId = message.getString("transfer_id")
        val fileState = incomingFiles[transferId] ?: return
        require(fileState.fromId == fromId && fileState.conversationId == groupId)
        val index = message.getInt("chunk_index")
        require(index in 0 until fileState.totalChunks)
        val chunk = org.bouncycastle.util.encoders.Base64.decode(message.getString("data"))
        require(chunk.isNotEmpty())
        fileState.chunks[index] = chunk
        setTransferProgress("Se primește ${fileState.filename} (${fileState.chunks.size * 100 / fileState.totalChunks}%)...")
    }

    private fun handleGroupFileEnd(groupId: String, fromId: String, message: JSONObject) {
        val transferId = message.getString("transfer_id")
        val fileState = incomingFiles[transferId] ?: return
        require(fileState.fromId == fromId && fileState.conversationId == groupId)
        require(fileState.chunks.size == fileState.totalChunks)
        require(fileState.chunks.values.sumOf { it.size.toLong() } == fileState.fileSize)
        incomingFiles.remove(transferId)
        val destFile = File(filesDir, fileState.filename)
        destFile.outputStream().use { output ->
            repeat(fileState.totalChunks) { index ->
                output.write(fileState.chunks[index] ?: error("Missing group file chunk $index"))
            }
        }
        storageManager.addMessage(
            ChatMessage(
                contactId = groupId,
                direction = "in",
                msgType = "file",
                content = "${fileState.filename}|${destFile.absolutePath}|${fileState.fileSize}"
            )
        )
        if (_selectedPeerId.value == groupId) refreshMessagesFor(groupId)
        setTransferProgress("✓ Primit: ${fileState.filename}", clearAfterMs = 5000)
        showToast("Fișier primit în grup: ${fileState.filename}")
    }

    private suspend fun handleGroupMetaMessage(fromId: String, payload: ByteArray) {
        try {
            val sessionKey = storageManager.getSessionKey(fromId) ?: run {
                sendHello(fromId)
                return
            }
            val json = JSONObject(
                String(decryptDirectMessage(fromId, sessionKey, payload), Charsets.UTF_8)
            )
            val groupId = json.getString("group_id")
            val group = storageManager.getGroup(groupId) ?: return

            when (json.getString("kind")) {
                "key_request" -> {
                    if (group.creatorId != identityManager.deviceId ||
                        json.optString("requester_id") != fromId) return
                    val client = signalingClient ?: return
                    val info = client.groupInfo(groupId) ?: return
                    val oldMembers = group.members.toSet()
                    updateGroupMembers(group, info)
                    if (fromId !in group.members) return
                    val secret = refreshGroupEpoch(group, oldMembers != group.members.toSet()) ?: return
                    distributeGroupEpoch(client, group, secret)
                }
                "epoch_key" -> {
                    if (fromId !in group.members) return
                    if (fromId != group.creatorId ||
                        json.optString("creator_id") != group.creatorId) return
                    val epoch = json.getLong("epoch")
                    if (epoch < group.epoch) return
                    val secret = org.bouncycastle.util.encoders.Base64.decode(json.getString("secret"))
                    require(secret.size == 32)
                    val masterKey = identityManager.masterKey ?: error("Identity is locked")
                    val existing = storageManager.loadGroupEpochSecret(groupId, epoch, masterKey)
                    if (epoch == group.epoch && existing != null) {
                        require(existing.contentEquals(secret)) { "Conflicting group epoch secret" }
                        secret.fill(0)
                        return
                    }
                    storageManager.saveGroupEpochSecret(
                        groupId, epoch, masterKey, secret
                    )
                    group.epoch = epoch
                    storageManager.addOrUpdateGroup(group)
                    secret.fill(0)
                    showToast("Cheia grupului ${group.name} a fost actualizată")
                    flushPendingGroupTexts(groupId)
                    flushPendingIncomingGroupFrames(groupId, epoch)
                }
                else -> throw IllegalArgumentException("Unknown group metadata message")
            }
        } catch (e: Exception) {
            Log.e(TAG, "handleGroupMetaMessage error: ${e.message}")
        }
    }

    private suspend fun syncCreatorGroupKeysToPeer(peerId: String) {
        val client = signalingClient ?: return
        if (!client.isConnected) return
        val masterKey = identityManager.masterKey ?: return
        for (group in storageManager.getGroups()) {
            if (group.creatorId != identityManager.deviceId) continue
            val info = client.groupInfo(group.groupId) ?: continue
            val oldMembers = group.members.toSet()
            val members = updateGroupMembers(group, info)
            if (peerId !in members) continue
            val secret = refreshGroupEpoch(group, oldMembers != group.members.toSet()) ?: continue
            try {
                sendGroupEpochToMember(client, group, peerId, secret)
            } finally {
                secret.fill(0)
            }
        }
    }

    private suspend fun flushPendingIncomingGroupFrames(groupId: String, epoch: Long) {
        val toProcess = synchronized(pendingIncomingGroupFramesLock) {
            val matching = pendingIncomingGroupFrames.filter { it.groupId == groupId && it.epoch == epoch }
            pendingIncomingGroupFrames.removeAll(matching)
            matching
        }
        if (toProcess.isEmpty()) return
        val group = storageManager.getGroup(groupId) ?: return
        val masterKey = identityManager.masterKey ?: return
        val epochSecret = storageManager.loadGroupEpochSecret(groupId, epoch, masterKey) ?: return

        for (item in toProcess) {
            try {
                val plaintext = groupSenderChain(group, epoch, item.fromId, epochSecret).use { chain ->
                    chain.decrypt(item.encryptedFrame).also {
                        storageManager.saveGroupSenderState(
                            groupId, epoch, item.fromId, masterKey, chain.exportState()
                        )
                    }
                }
                val message = JSONObject(String(plaintext, Charsets.UTF_8))
                when (message.getString("kind")) {
                    "text" -> {
                        val senderName = storageManager.getContact(item.fromId)?.displayName ?: item.fromId.take(6)
                        storageManager.addMessage(
                            ChatMessage(
                                contactId = groupId,
                                direction = "in",
                                msgType = "text",
                                content = "[$senderName]: ${message.getString("text")}"
                            )
                        )
                        if (_selectedPeerId.value == groupId) refreshMessagesFor(groupId)
                        showToast("Mesaj în grupul ${group.name}")
                    }
                    "file_start" -> handleGroupFileStart(groupId, item.fromId, message)
                    "file_chunk" -> handleGroupFileChunk(groupId, item.fromId, message)
                    "file_end" -> handleGroupFileEnd(groupId, item.fromId, message)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to process buffered group frame for $groupId: ${e.message}")
            }
        }
    }

    private fun requestGroupEpochsFromPeer(peerId: String) {
        val masterKey = identityManager.masterKey ?: return
        storageManager.getGroups()
            .filter { it.creatorId == peerId }
            .filter { group ->
                group.epoch == 0L ||
                    storageManager.loadGroupEpochSecret(group.groupId, group.epoch, masterKey) == null
            }
            .forEach(::requestGroupEpoch)
    }

    private suspend fun sendGroupEpochToMember(
        client: SignalingClient,
        group: GroupChat,
        memberId: String,
        secret: ByteArray,
        epoch: Long = group.epoch
    ): Boolean {
        val sessionKey = storageManager.getSessionKey(memberId) ?: run {
            sendHello(memberId)
            return false
        }
        val keyPackage = JSONObject()
            .put("kind", "epoch_key")
            .put("group_id", group.groupId)
            .put("epoch", epoch)
            .put("creator_id", identityManager.deviceId)
            .put("secret", org.bouncycastle.util.encoders.Base64.toBase64String(secret))
            .toString().toByteArray(Charsets.UTF_8)
        val encrypted = encryptDirectMessage(memberId, sessionKey, keyPackage)
        return client.relaySend(memberId, byteArrayOf(Constants.MSG_GROUP_META) + encrypted)
    }
}
