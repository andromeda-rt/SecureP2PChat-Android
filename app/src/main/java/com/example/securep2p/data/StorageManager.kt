package com.example.securep2p.data

import android.content.Context
import android.content.SharedPreferences
import com.example.securep2p.crypto.CryptoEngine
import org.json.JSONArray
import org.json.JSONObject
import org.bouncycastle.util.encoders.Base64
import java.io.File
import java.util.UUID

data class Contact(
    val deviceId: String,
    var displayName: String,
    var publicKey: String = "",
    var fingerprint: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    var lastSeen: Long = System.currentTimeMillis(),
    var isOnline: Boolean = false
)

data class ChatMessage(
    val id: String = UUID.randomUUID().toString(),
    val contactId: String,
    val direction: String, // "in" or "out"
    val msgType: String, // "text" or "file"
    val content: String,
    val timestamp: Long = System.currentTimeMillis(),
    var status: String = "sent" // "pending", "sent", "delivered"
)

data class GroupChat(
    val groupId: String,
    var name: String,
    var inviteCode: String,
    val members: MutableList<String> = mutableListOf(),
    var creatorId: String = "",
    var epoch: Long = 0
)

data class AppSettings(
    val signalHost: String = "10.0.2.2", // 10.0.2.2 points to host PC in Android emulator
    val signalPort: Int = 37422,
    val useTls: Boolean = true,
    val useTor: Boolean = false,
    val torSocksHost: String = "127.0.0.1",
    val torSocksPort: Int = 9050
)

class StorageManager(private val context: Context) {
    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences("secure_p2p_prefs", Context.MODE_PRIVATE)
    }

    private val contactsFile: File by lazy { File(context.filesDir, "contacts.json") }
    private val messagesFile: File by lazy { File(context.filesDir, "messages.json") }
    private val groupsFile: File by lazy { File(context.filesDir, "groups.json") }

    private val contactsMap = mutableMapOf<String, Contact>()
    private val messagesList = mutableListOf<ChatMessage>()
    private val groupsMap = mutableMapOf<String, GroupChat>()
    private val sessionKeysMap = mutableMapOf<String, ByteArray>()

    init {
        loadContacts()
        loadMessages()
        loadGroups()
    }

    // --- Settings ---
    fun loadSettings(): AppSettings {
        return AppSettings(
            signalHost = prefs.getString("signal_host", "10.0.2.2") ?: "10.0.2.2",
            signalPort = prefs.getInt("signal_port", 37422),
            useTls = prefs.getBoolean("use_tls", true),
            useTor = prefs.getBoolean("use_tor", false),
            torSocksHost = prefs.getString("tor_socks_host", "127.0.0.1") ?: "127.0.0.1",
            torSocksPort = prefs.getInt("tor_socks_port", 9050)
        )
    }

    fun saveSettings(settings: AppSettings) {
        prefs.edit()
            .putString("signal_host", settings.signalHost.trim())
            .putInt("signal_port", settings.signalPort)
            .putBoolean("use_tls", settings.useTls)
            .putBoolean("use_tor", settings.useTor)
            .putString("tor_socks_host", settings.torSocksHost.trim())
            .putInt("tor_socks_port", settings.torSocksPort)
            .apply()
    }

    // --- Contacts ---
    @Synchronized
    fun getContacts(): List<Contact> = contactsMap.values.toList()

    @Synchronized
    fun getContact(deviceId: String): Contact? = contactsMap[deviceId]

    @Synchronized
    fun addOrUpdateContact(contact: Contact) {
        contactsMap[contact.deviceId] = contact
        saveContacts()
    }

    @Synchronized
    fun isContactHidden(deviceId: String): Boolean =
        prefs.getStringSet("hidden_contacts", emptySet())?.contains(deviceId) == true

    @Synchronized
    fun restoreContact(deviceId: String) {
        val hidden = prefs.getStringSet("hidden_contacts", emptySet()).orEmpty().toMutableSet()
        if (hidden.remove(deviceId)) {
            prefs.edit().putStringSet("hidden_contacts", hidden).apply()
        }
    }

    @Synchronized
    fun removeContact(deviceId: String) {
        contactsMap.remove(deviceId)
        saveContacts()
    }

    private fun loadContacts() {
        if (!contactsFile.exists()) return
        try {
            val json = JSONArray(contactsFile.readText(Charsets.UTF_8))
            for (i in 0 until json.length()) {
                val obj = json.getJSONObject(i)
                val c = Contact(
                    deviceId = obj.getString("device_id"),
                    displayName = obj.getString("display_name"),
                    publicKey = obj.optString("public_key", ""),
                    fingerprint = obj.optString("fingerprint", ""),
                    createdAt = obj.optLong("created_at", System.currentTimeMillis()),
                    lastSeen = obj.optLong("last_seen", System.currentTimeMillis()),
                    isOnline = false
                )
                contactsMap[c.deviceId] = c
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun saveContacts() {
        try {
            val json = JSONArray()
            for (c in contactsMap.values) {
                val obj = JSONObject().apply {
                    put("device_id", c.deviceId)
                    put("display_name", c.displayName)
                    put("public_key", c.publicKey)
                    put("fingerprint", c.fingerprint)
                    put("created_at", c.createdAt)
                    put("last_seen", c.lastSeen)
                }
                json.put(obj)
            }
            contactsFile.writeText(json.toString(), Charsets.UTF_8)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    // --- Messages ---
    @Synchronized
    fun getMessages(contactId: String): List<ChatMessage> {
        return messagesList.filter { it.contactId == contactId }.sortedBy { it.timestamp }
    }

    @Synchronized
    fun addMessage(msg: ChatMessage) {
        messagesList.add(msg)
        saveMessages()
    }

    @Synchronized
    fun updateMessageStatus(messageId: String, status: String) {
        val message = messagesList.firstOrNull { it.id == messageId } ?: return
        message.status = status
        saveMessages()
    }

    @Synchronized
    fun getPendingOutgoingTextMessages(contactId: String): List<ChatMessage> =
        messagesList.filter {
            it.contactId == contactId &&
                it.direction == "out" &&
                it.msgType == "text" &&
                it.status == "pending"
        }.sortedBy { it.timestamp }

    @Synchronized
    fun clearMessages(contactId: String) {
        messagesList.removeAll { it.contactId == contactId }
        saveMessages()
    }

    private fun loadMessages() {
        if (!messagesFile.exists()) return
        try {
            val json = JSONArray(messagesFile.readText(Charsets.UTF_8))
            for (i in 0 until json.length()) {
                val obj = json.getJSONObject(i)
                val m = ChatMessage(
                    id = obj.optString("id", UUID.randomUUID().toString()),
                    contactId = obj.getString("contact_id"),
                    direction = obj.getString("direction"),
                    msgType = obj.getString("msg_type"),
                    content = obj.getString("content"),
                    timestamp = obj.getLong("timestamp"),
                    status = obj.optString("status", "sent")
                )
                messagesList.add(m)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun saveMessages() {
        try {
            val json = JSONArray()
            // Keep last 500 messages to keep mobile storage lightweight and fast
            val toSave = if (messagesList.size > 500) messagesList.takeLast(500) else messagesList
            for (m in toSave) {
                val obj = JSONObject().apply {
                    put("id", m.id)
                    put("contact_id", m.contactId)
                    put("direction", m.direction)
                    put("msg_type", m.msgType)
                    put("content", m.content)
                    put("timestamp", m.timestamp)
                    put("status", m.status)
                }
                json.put(obj)
            }
            messagesFile.writeText(json.toString(), Charsets.UTF_8)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    // --- Groups ---
    @Synchronized
    fun getGroups(): List<GroupChat> = groupsMap.values.toList()

    @Synchronized
    fun getGroup(groupId: String): GroupChat? = groupsMap[groupId]

    @Synchronized
    fun addOrUpdateGroup(group: GroupChat) {
        groupsMap[group.groupId] = group
        saveGroups()
    }

    @Synchronized
    fun removeGroup(groupId: String) {
        groupsMap.remove(groupId)
        messagesList.removeAll { it.contactId == groupId }
        removeGroupCryptoState(groupId)
        saveGroups()
        saveMessages()
    }

    @Synchronized
    fun removeGroupCryptoState(groupId: String) {
        val editor = prefs.edit()
        prefs.all.keys
            .filter {
                it.startsWith("group_secret_${groupId}_") ||
                    it.startsWith("group_sender_${groupId}_")
            }
            .forEach(editor::remove)
        check(editor.commit()) { "Could not remove group cryptographic state" }
    }

    private fun loadGroups() {
        if (!groupsFile.exists()) return
        try {
            val json = JSONArray(groupsFile.readText(Charsets.UTF_8))
            for (i in 0 until json.length()) {
                val obj = json.getJSONObject(i)
                val gid = obj.getString("group_id")
                val name = obj.getString("name")
                val code = obj.optString("invite_code", "")
                val membersArr = obj.optJSONArray("members")
                val membersList = mutableListOf<String>()
                if (membersArr != null) {
                    for (j in 0 until membersArr.length()) {
                        membersList.add(membersArr.getString(j))
                    }
                }
                groupsMap[gid] = GroupChat(
                    gid,
                    name,
                    code,
                    membersList,
                    obj.optString("creator_id", ""),
                    obj.optLong("epoch", 0)
                )
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun saveGroups() {
        try {
            val json = JSONArray()
            for (g in groupsMap.values) {
                val obj = JSONObject().apply {
                    put("group_id", g.groupId)
                    put("name", g.name)
                    put("invite_code", g.inviteCode)
                    put("creator_id", g.creatorId)
                    put("epoch", g.epoch)
                    val arr = JSONArray()
                    for (m in g.members) arr.put(m)
                    put("members", arr)
                }
                json.put(obj)
            }
            groupsFile.writeText(json.toString(), Charsets.UTF_8)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    @Synchronized
    fun setSessionKey(deviceId: String, key: ByteArray) {
        sessionKeysMap[deviceId] = key
    }

    @Synchronized
    fun clearSessionKey(deviceId: String) {
        sessionKeysMap.remove(deviceId)
    }

    @Synchronized
    fun getSessionKey(deviceId: String): ByteArray? {
        return sessionKeysMap[deviceId]
    }

    @Synchronized
    fun saveForwardSecrecyState(
        localDeviceId: String,
        peerDeviceId: String,
        masterKey: ByteArray,
        state: ByteArray
    ) {
        require(localDeviceId.isNotBlank() && peerDeviceId.isNotBlank()) {
            "Participant IDs are required for FS2 state"
        }
        require(masterKey.size == 32) { "Master key must be 32 bytes" }
        val encrypted = CryptoEngine.encryptBytes(
            state,
            masterKey,
            forwardSecrecyStorageContext(localDeviceId, peerDeviceId)
        )
        check(prefs.edit()
            .putString(
                forwardSecrecyPreferenceKey(localDeviceId, peerDeviceId),
                Base64.toBase64String(encrypted)
            )
            .putBoolean(forwardSecrecyInitializedKey(localDeviceId, peerDeviceId), true)
            .commit()) {
            "Could not persist FS2 state"
        }
    }

    @Synchronized
    fun loadForwardSecrecyState(
        localDeviceId: String,
        peerDeviceId: String,
        masterKey: ByteArray
    ): ByteArray? {
        require(localDeviceId.isNotBlank() && peerDeviceId.isNotBlank()) {
            "Participant IDs are required for FS2 state"
        }
        require(masterKey.size == 32) { "Master key must be 32 bytes" }
        val encoded = prefs.getString(
            forwardSecrecyPreferenceKey(localDeviceId, peerDeviceId),
            null
        ) ?: run {
            check(!prefs.getBoolean(forwardSecrecyInitializedKey(localDeviceId, peerDeviceId), false)) {
                "FS2 state is missing; refusing to reset the ratchet"
            }
            return null
        }
        val encrypted = try {
            Base64.decode(encoded)
        } catch (e: IllegalArgumentException) {
            throw IllegalStateException("Stored FS2 state is corrupt", e)
        }
        require(Base64.toBase64String(encrypted) == encoded) {
            "Stored FS2 state encoding is invalid"
        }
        return CryptoEngine.decryptBytes(
            encrypted,
            masterKey,
            forwardSecrecyStorageContext(localDeviceId, peerDeviceId)
        )
    }

    @Synchronized
    fun clearForwardSecrecyState(localDeviceId: String, peerDeviceId: String) {
        prefs.edit()
            .remove(forwardSecrecyPreferenceKey(localDeviceId, peerDeviceId))
            .remove(forwardSecrecyInitializedKey(localDeviceId, peerDeviceId))
            .commit()
    }

    @Synchronized
    fun saveGroupEpochSecret(groupId: String, epoch: Long, masterKey: ByteArray, secret: ByteArray) {
        require(groupId.isNotBlank() && epoch > 0 && masterKey.size == 32 && secret.size == 32)
        val encrypted = CryptoEngine.encryptBytes(
            secret,
            masterKey,
            groupSecretContext(groupId, epoch)
        )
        check(prefs.edit().putString(groupSecretPreferenceKey(groupId, epoch), Base64.toBase64String(encrypted)).commit()) {
            "Could not persist group epoch secret"
        }
    }

    @Synchronized
    fun loadGroupEpochSecret(groupId: String, epoch: Long, masterKey: ByteArray): ByteArray? {
        require(groupId.isNotBlank() && epoch > 0 && masterKey.size == 32)
        val encoded = prefs.getString(groupSecretPreferenceKey(groupId, epoch), null) ?: return null
        val encrypted = Base64.decode(encoded)
        require(Base64.toBase64String(encrypted) == encoded) { "Invalid group secret encoding" }
        return CryptoEngine.decryptBytes(encrypted, masterKey, groupSecretContext(groupId, epoch))
    }

    @Synchronized
    fun saveGroupSenderState(
        groupId: String,
        epoch: Long,
        senderId: String,
        masterKey: ByteArray,
        state: ByteArray
    ) {
        require(groupId.isNotBlank() && epoch > 0 && senderId.isNotBlank() && masterKey.size == 32)
        val encrypted = CryptoEngine.encryptBytes(
            state,
            masterKey,
            groupSenderContext(groupId, epoch, senderId)
        )
        check(prefs.edit().putString(
            groupSenderPreferenceKey(groupId, epoch, senderId),
            Base64.toBase64String(encrypted)
        ).commit()) { "Could not persist group sender-key state" }
    }

    @Synchronized
    fun loadGroupSenderState(
        groupId: String,
        epoch: Long,
        senderId: String,
        masterKey: ByteArray
    ): ByteArray? {
        require(groupId.isNotBlank() && epoch > 0 && senderId.isNotBlank() && masterKey.size == 32)
        val encoded = prefs.getString(groupSenderPreferenceKey(groupId, epoch, senderId), null) ?: return null
        val encrypted = Base64.decode(encoded)
        require(Base64.toBase64String(encrypted) == encoded) { "Invalid group sender state encoding" }
        return CryptoEngine.decryptBytes(encrypted, masterKey, groupSenderContext(groupId, epoch, senderId))
    }

    @Synchronized
    fun saveTreeKEMState(
        groupId: String,
        epoch: Long,
        masterKey: ByteArray,
        state: ByteArray
    ) {
        require(groupId.isNotBlank() && epoch >= 0 && masterKey.size == 32)
        val encrypted = CryptoEngine.encryptBytes(
            state,
            masterKey,
            "treekem_state|$groupId|$epoch".toByteArray(Charsets.UTF_8)
        )
        check(prefs.edit().putString(
            "treekem_${groupId}_$epoch",
            Base64.toBase64String(encrypted)
        ).commit()) { "Could not persist TreeKEM state" }
    }

    @Synchronized
    fun loadTreeKEMState(
        groupId: String,
        epoch: Long,
        masterKey: ByteArray
    ): ByteArray? {
        require(groupId.isNotBlank() && epoch >= 0 && masterKey.size == 32)
        val encoded = prefs.getString("treekem_${groupId}_$epoch", null) ?: return null
        val encrypted = Base64.decode(encoded)
        return CryptoEngine.decryptBytes(
            encrypted,
            masterKey,
            "treekem_state|$groupId|$epoch".toByteArray(Charsets.UTF_8)
        )
    }

    @Synchronized
    fun removeChat(deviceId: String) {
        if (contactsMap.remove(deviceId) != null) {
            val hidden = prefs.getStringSet("hidden_contacts", emptySet()).orEmpty().toMutableSet()
            hidden.add(deviceId)
            prefs.edit().putStringSet("hidden_contacts", hidden).apply()
        }
        sessionKeysMap.remove(deviceId)
        groupsMap.remove(deviceId)
        messagesList.removeAll { it.contactId == deviceId }
        saveContacts()
        saveGroups()
        saveMessages()
    }

    private fun forwardSecrecyPreferenceKey(localDeviceId: String, peerDeviceId: String): String =
        "fs2_state_${localDeviceId}_$peerDeviceId"

    private fun forwardSecrecyInitializedKey(localDeviceId: String, peerDeviceId: String): String =
        "fs2_initialized_${localDeviceId}_$peerDeviceId"

    private fun forwardSecrecyStorageContext(localDeviceId: String, peerDeviceId: String): ByteArray =
        "fs2-state|$localDeviceId|$peerDeviceId".toByteArray(Charsets.UTF_8)

    private fun groupSecretPreferenceKey(groupId: String, epoch: Long): String =
        "group_secret_${groupId}_$epoch"

    private fun groupSenderPreferenceKey(groupId: String, epoch: Long, senderId: String): String =
        "group_sender_${groupId}_${epoch}_$senderId"

    private fun groupSecretContext(groupId: String, epoch: Long): ByteArray =
        "group-secret|$groupId|$epoch".toByteArray(Charsets.UTF_8)

    private fun groupSenderContext(groupId: String, epoch: Long, senderId: String): ByteArray =
        "group-sender|$groupId|$epoch|$senderId".toByteArray(Charsets.UTF_8)
}
