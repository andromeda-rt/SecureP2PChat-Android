package com.example.securep2p.data

import android.content.Context
import android.util.Base64
import android.util.Log
import com.example.securep2p.crypto.CryptoEngine
import com.example.securep2p.protocol.PairCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.EOFException
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class RelayMessage(
    val from: String,
    val payload: ByteArray,
    val id: String = ""
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RelayMessage) return false
        return from == other.from && payload.contentEquals(other.payload) && id == other.id
    }

    override fun hashCode(): Int = 31 * (31 * from.hashCode() + payload.contentHashCode()) + id.hashCode()
}

class SignalingClient(
    context: Context,
    var host: String,
    var port: Int,
    var useTls: Boolean = true,
    var useTor: Boolean = false,
    var torSocksHost: String = "127.0.0.1",
    var torSocksPort: Int = 9050
) {
    private val appContext = context.applicationContext

    companion object {
        private const val TAG = "SignalingClient"
    }

    private var socket: Socket? = null
    private var reader: BufferedReader? = null
    private var writer: BufferedWriter? = null
    private val mutex = Mutex()

    var isConnected: Boolean = false
        private set

    var lastError: String = ""
        private set

    private var deviceId: String? = null
    private var signingPrivateKey: ByteArray? = null
    private var verifyKeyHex: String? = null
    private var publicKeyHex: String? = null
    private var displayName: String? = null
    var sessionToken: String? = null
        private set

    @OptIn(ExperimentalStdlibApi::class)
    fun setIdentity(
        deviceId: String,
        signingPrivateKey: ByteArray,
        verifyKeyBytes: ByteArray,
        publicKeyBytes: ByteArray,
        displayName: String
    ) {
        this.deviceId = deviceId
        this.signingPrivateKey = signingPrivateKey
        this.verifyKeyHex = verifyKeyBytes.toHexString()
        this.publicKeyHex = publicKeyBytes.toHexString()
        this.displayName = displayName
    }

    private fun getTrustAllSocketFactory(): SSLContext {
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, trustAllCerts, SecureRandom())
        return sslContext
    }

    private fun verifyOrPinRelayCertificate(targetHost: String, targetPort: Int, socket: SSLSocket) {
        val certificate = socket.session.peerCertificates.firstOrNull() as? X509Certificate
            ?: throw IOException("Relay did not provide an X.509 certificate")
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }
        val endpoint = "$targetHost:$targetPort".lowercase()
        val pinKey = "tls_pin_${MessageDigest.getInstance("SHA-256")
            .digest(endpoint.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }}"
        val preferences = appContext.getSharedPreferences("relay_security", Context.MODE_PRIVATE)
        val pinnedFingerprint = preferences.getString(pinKey, null)
        if (pinnedFingerprint == null) {
            if (!preferences.edit().putString(pinKey, fingerprint).commit()) {
                throw IOException("Could not save the relay TLS certificate pin")
            }
            Log.i(TAG, "Pinned TLS certificate for $targetHost:$targetPort")
        } else if (!MessageDigest.isEqual(
                pinnedFingerprint.toByteArray(Charsets.US_ASCII),
                fingerprint.toByteArray(Charsets.US_ASCII)
            )
        ) {
            throw IOException("Relay TLS certificate pin mismatch")
        }
    }

    private fun resolveRelayEndpoint(rawHost: String, defaultPort: Int): Pair<String, Int> {
        val normalizedHost = rawHost.trim().ifEmpty { "10.0.2.2" }
        val withoutScheme = normalizedHost
            .replaceFirst(Regex("^https?://", RegexOption.IGNORE_CASE), "")
        val authority = withoutScheme.substringBefore('/').substringBefore('?').substringBefore('#')

        val hostName: String
        val targetPort: Int
        if (authority.startsWith("[")) {
            val closingBracket = authority.indexOf(']')
            require(closingBracket > 1) { "Invalid relay host" }
            hostName = authority.substring(1, closingBracket)
            val portSuffix = authority.substring(closingBracket + 1)
            targetPort = if (portSuffix.startsWith(":")) {
                portSuffix.substring(1).toIntOrNull() ?: throw IllegalArgumentException("Invalid relay port")
            } else {
                require(portSuffix.isEmpty()) { "Invalid relay host" }
                defaultPort
            }
        } else {
            val lastColon = authority.lastIndexOf(':')
            val hasExplicitPort = lastColon > 0 && authority.substring(lastColon + 1).all { it.isDigit() }
            hostName = if (hasExplicitPort) authority.substring(0, lastColon) else authority
            targetPort = if (hasExplicitPort) {
                authority.substring(lastColon + 1).toIntOrNull()
                    ?: throw IllegalArgumentException("Invalid relay port")
            } else {
                defaultPort
            }
        }

        require(hostName.isNotBlank()) { "Relay host is empty" }
        require(targetPort in 1..65535) { "Relay port must be between 1 and 65535" }
        return hostName to targetPort
    }

    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        close()
        try {
            val (targetHost, targetPort) = resolveRelayEndpoint(host, port)

            val rawSocket = if (useTor) {
                val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress(torSocksHost, torSocksPort))
                Socket(proxy)
            } else {
                Socket()
            }

            rawSocket.tcpNoDelay = true
            rawSocket.soTimeout = 60000

            val endpoint = if (useTor) {
                InetSocketAddress.createUnresolved(targetHost, targetPort)
            } else {
                InetSocketAddress(targetHost, targetPort)
            }

            rawSocket.connect(endpoint, if (useTor) 60000 else 15000)

            val activeSocket = if (useTls) {
                val sslCtx = getTrustAllSocketFactory()
                val sslSock = sslCtx.socketFactory.createSocket(rawSocket, targetHost, targetPort, true) as SSLSocket
                try {
                    val supported = sslSock.supportedProtocols
                    val enabled = mutableListOf<String>()
                    if ("TLSv1.2" in supported) enabled.add("TLSv1.2")
                    if ("TLSv1.3" in supported) enabled.add("TLSv1.3")
                    if ("TLSv1.1" in supported) enabled.add("TLSv1.1")
                    if ("TLSv1" in supported) enabled.add("TLSv1")
                    if (enabled.isNotEmpty()) {
                        sslSock.enabledProtocols = enabled.toTypedArray()
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Could not set enabledProtocols: ${e.message}")
                }
                sslSock.startHandshake()
                verifyOrPinRelayCertificate(targetHost, targetPort, sslSock)
                sslSock
            } else {
                rawSocket
            }

            reader = BufferedReader(InputStreamReader(activeSocket.getInputStream(), Charsets.UTF_8), 1024 * 64)
            writer = BufferedWriter(OutputStreamWriter(activeSocket.getOutputStream(), Charsets.UTF_8), 1024 * 64)
            socket = activeSocket
            isConnected = true
            lastError = ""
            Log.d(TAG, "Connected to $targetHost:$targetPort (TLS=$useTls, Tor=$useTor)")
            true
        } catch (e: Exception) {
            lastError = e.localizedMessage ?: "Connection error"
            Log.e(TAG, "Connect failed: $lastError")
            close()
            false
        }
    }

    suspend fun close() = withContext(Dispatchers.IO) {
        isConnected = false
        sessionToken = null
        try {
            reader?.close()
        } catch (e: Exception) { /* ignore */ }
        try {
            writer?.close()
        } catch (e: Exception) { /* ignore */ }
        try {
            socket?.close()
        } catch (e: Exception) { /* ignore */ }
        reader = null
        writer = null
        socket = null
    }

    suspend fun ensureConnected(): Boolean {
        if (isConnected && socket != null && !socket!!.isClosed) {
            return true
        }
        return connect()
    }

    private suspend fun request(obj: JSONObject): JSONObject? = withContext(Dispatchers.IO) {
        for (attempt in 0 until 3) {
            var connected = false
            mutex.withLock {
                if (!ensureConnected()) {
                    return@withLock
                }
                connected = true
                try {
                    val token = sessionToken
                    if (token.isNullOrEmpty()) {
                        obj.remove("session_token")
                    } else {
                        obj.put("session_token", token)
                    }
                    val w = writer ?: throw IllegalStateException("Writer is null")
                    val r = reader ?: throw IllegalStateException("Reader is null")
                    w.write(obj.toString())
                    w.write("\n")
                    w.flush()

                    val line = r.readLine()
                    if (line != null) {
                        return@withContext JSONObject(line.trim())
                    }
                    throw EOFException("Serverul a închis conexiunea fără răspuns")
                } catch (e: Exception) {
                    lastError = e.localizedMessage ?: "Eroare la cererea către server"
                    Log.w(TAG, "Request failed (attempt $attempt): $lastError")
                    close()
                }
            }
            if (!connected) {
                kotlinx.coroutines.delay(400L * (attempt + 1))
                continue
            }
            kotlinx.coroutines.delay(300L * (attempt + 1))
        }
        null
    }

    @OptIn(ExperimentalStdlibApi::class)
    suspend fun register(ipv4: String? = null, ipv6: String? = null, port: Int = 37421): Boolean {
        val devId = deviceId ?: run {
            lastError = "Lipsește ID-ul dispozitivului"
            return false
        }
        val signingKey = signingPrivateKey ?: run {
            lastError = "Lipsește cheia de semnare"
            return false
        }
        val ts = System.currentTimeMillis() / 1000

        val canonical = "SecureP2PChat-register-v2|$devId|${ipv4 ?: ""}|${ipv6 ?: ""}|$port|$ts|${publicKeyHex ?: ""}|${displayName ?: ""}"
        val sig = CryptoEngine.sign(signingKey, canonical.toByteArray(Charsets.UTF_8)).toHexString()

        val req = JSONObject().apply {
            put("cmd", "register")
            put("device_id", devId)
            put("ipv4", ipv4 ?: "")
            put("ipv6", ipv6 ?: "")
            put("port", port)
            put("ts", ts)
            put("verify_key", verifyKeyHex ?: "")
            put("signature", sig)
            put("public_key", publicKeyHex ?: "")
            put("display_name", displayName ?: "")
        }

        val resp = request(req)
        if (resp != null && resp.optBoolean("ok", false)) {
            val token = resp.optString("session_token")
            if (token.isNotEmpty()) {
                sessionToken = token
            }
            lastError = ""
            return true
        }
        lastError = if (resp == null) {
            lastError.ifEmpty { "Serverul nu a răspuns la înregistrare" }
        } else {
            resp.optString("error").ifBlank {
                resp.optString("message").ifBlank { "Serverul a refuzat înregistrarea" }
            }
        }
        Log.e(TAG, "Registration failed: $lastError")
        return false
    }

    suspend fun heartbeat(ipv4: String? = null, ipv6: String? = null, port: Int = 0): Boolean {
        val devId = deviceId ?: return false
        val token = sessionToken
        val req = JSONObject().apply {
            put("cmd", "heartbeat")
            if (!token.isNullOrEmpty()) {
                put("session_token", token)
            }
            put("device_id", devId)
            put("ipv4", ipv4 ?: "")
            put("ipv6", ipv6 ?: "")
            put("port", port)
        }
        val resp = request(req)
        if (resp != null && resp.optBoolean("ok", false)) {
            val newToken = resp.optString("session_token")
            if (newToken.isNotEmpty()) {
                sessionToken = newToken
            }
            return true
        }
        return false
    }

    @OptIn(ExperimentalStdlibApi::class)
    suspend fun pairCreate(): String? {
        val devId = deviceId ?: return null
        val signingKey = signingPrivateKey ?: return null
        val ts = System.currentTimeMillis() / 1000
        val canonical = "$devId|pair_create|$ts"
        val sig = CryptoEngine.sign(signingKey, canonical.toByteArray(Charsets.UTF_8)).toHexString()

        val req = JSONObject().apply {
            put("cmd", "pair_create")
            put("device_id", devId)
            put("verify_key", verifyKeyHex ?: "")
            put("signature", sig)
            put("ts", ts)
            put("public_key", publicKeyHex ?: "")
            put("display_name", displayName ?: "Android-${devId.take(6)}")
        }

        val resp = request(req)
        if (resp != null && resp.optBoolean("ok", false)) {
            return resp.optString("pair_code")
        }
        return null
    }

    suspend fun pairStatus(code: String): JSONObject? {
        val normalizedCode = PairCode.normalize(code) ?: run {
            lastError = "Codul de asociere trebuie să aibă 6 caractere valide"
            return null
        }
        val req = JSONObject().apply {
            put("cmd", "pair_status")
            put("pair_code", normalizedCode)
            put("device_id", deviceId ?: "")
        }
        return request(req)
    }

    suspend fun pairJoin(code: String): JSONObject? {
        val devId = deviceId ?: return null
        val normalizedCode = PairCode.normalize(code) ?: run {
            lastError = "Codul de asociere trebuie să aibă 6 caractere valide"
            return null
        }
        val req = JSONObject().apply {
            put("cmd", "pair_join")
            put("pair_code", normalizedCode)
            put("device_id", devId)
            put("public_key", publicKeyHex ?: "")
            put("verify_key", verifyKeyHex ?: "")
            put("display_name", displayName ?: "")
        }
        val resp = request(req)
        if (resp != null && !resp.optBoolean("ok", false)) {
            lastError = resp.optString("error").ifBlank {
                resp.optString("message").ifBlank { "Releul a refuzat codul de asociere" }
            }
        }
        return resp
    }

    suspend fun relaySend(toDeviceId: String, payload: ByteArray): Boolean {
        val b64 = Base64.encodeToString(payload, Base64.NO_WRAP)
        val req = JSONObject().apply {
            put("cmd", "relay_send")
            put("to", toDeviceId)
            put("payload", b64)
        }
        val resp = request(req)
        return resp != null && resp.optBoolean("ok", false)
    }

    suspend fun relayPoll(): List<RelayMessage>? {
        val req = JSONObject().apply {
            put("cmd", "relay_poll")
        }
        val resp = request(req) ?: return null
        if (!resp.optBoolean("ok", false)) {
            val err = resp.optString("error")
            if (err.contains("auth", ignoreCase = true) || err.contains("token", ignoreCase = true)) {
                sessionToken = null
            }
            return null
        }
        val arr = resp.optJSONArray("messages") ?: JSONArray()
        val list = mutableListOf<RelayMessage>()
        for (i in 0 until arr.length()) {
            val it = arr.getJSONObject(i)
            val fromId = it.optString("from")
            val b64 = it.optString("payload")
            if (fromId.isNotEmpty() && b64.isNotEmpty()) {
                try {
                    val raw = Base64.decode(b64, Base64.DEFAULT)
                    list.add(RelayMessage(fromId, raw, it.optString("id")))
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to decode relay payload: ${e.message}")
                }
            }
        }
        return list
    }

    suspend fun relayAck(messageIds: List<String>): Boolean {
        val ids = messageIds.filter { it.isNotBlank() }.distinct()
        if (ids.isEmpty()) return true
        val req = JSONObject().apply {
            put("cmd", "relay_ack")
            put("ids", JSONArray().apply { ids.forEach { put(it) } })
        }
        val resp = request(req)
        if (resp == null || !resp.optBoolean("ok", false)) {
            val error = lastError.ifEmpty { resp?.optString("error").orEmpty() }
            Log.w(TAG, "Relay acknowledgment failed: $error")
            return false
        }
        return true
    }

    suspend fun lookup(targetDeviceId: String): JSONObject? {
        val req = JSONObject().apply {
            put("cmd", "lookup")
            put("device_id", targetDeviceId)
        }
        val resp = request(req)
        return if (resp != null && resp.optBoolean("ok", false)) resp else null
    }

    @OptIn(ExperimentalStdlibApi::class)
    suspend fun groupCreate(name: String): JSONObject? {
        val devId = deviceId ?: return null
        val signingKey = signingPrivateKey ?: return null
        val groupName = name.trim().ifEmpty { "Grup" }
        val ts = System.currentTimeMillis() / 1000
        val canonical = "$devId|group_create|$ts|$groupName"
        val sig = CryptoEngine.sign(signingKey, canonical.toByteArray(Charsets.UTF_8)).toHexString()

        val req = JSONObject().apply {
            put("cmd", "group_create")
            put("device_id", devId)
            put("verify_key", verifyKeyHex ?: "")
            put("signature", sig)
            put("ts", ts)
            put("name", groupName)
            put("public_key", publicKeyHex ?: "")
            put("display_name", displayName ?: "")
        }
        val resp = request(req)
        return if (resp != null && resp.optBoolean("ok", false)) resp else null
    }

    @OptIn(ExperimentalStdlibApi::class)
    suspend fun groupJoin(inviteCode: String): JSONObject? {
        val devId = deviceId ?: return null
        val signingKey = signingPrivateKey ?: return null
        val code = inviteCode.trim().uppercase()
        val ts = System.currentTimeMillis() / 1000
        val canonical = "$devId|group_join|$ts|$code"
        val sig = CryptoEngine.sign(signingKey, canonical.toByteArray(Charsets.UTF_8)).toHexString()

        val req = JSONObject().apply {
            put("cmd", "group_join")
            put("device_id", devId)
            put("verify_key", verifyKeyHex ?: "")
            put("signature", sig)
            put("ts", ts)
            put("invite_code", code)
            put("public_key", publicKeyHex ?: "")
            put("display_name", displayName ?: "")
        }
        val resp = request(req)
        return if (resp != null && resp.optBoolean("ok", false)) resp else null
    }

    @OptIn(ExperimentalStdlibApi::class)
    suspend fun groupInfo(groupId: String): JSONObject? {
        val devId = deviceId ?: return null
        val signingKey = signingPrivateKey ?: return null
        val gid = groupId.trim()
        val ts = System.currentTimeMillis() / 1000
        val canonical = "$devId|group_info|$ts|$gid"
        val sig = CryptoEngine.sign(signingKey, canonical.toByteArray(Charsets.UTF_8)).toHexString()

        val req = JSONObject().apply {
            put("cmd", "group_info")
            put("device_id", devId)
            put("verify_key", verifyKeyHex ?: "")
            put("signature", sig)
            put("ts", ts)
            put("group_id", gid)
        }
        val resp = request(req)
        return if (resp != null && resp.optBoolean("ok", false)) resp else null
    }
}
