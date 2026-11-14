package com.example.securep2p.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.util.encoders.Base64
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.TreeMap

/**
 * FS2 symmetric message-key ratchet. The session key is still derived from the
 * existing static X25519 exchange; this is not a full Double Ratchet.
 */
class ForwardSecrecyChain(sessionKey: ByteArray, myId: String, peerId: String) {
    val myId: String
    val peerId: String
    private val sessionId: ByteArray
    private var sendChainKey: ByteArray
    private var receiveChainKey: ByteArray
    private var sendNumber = 0L
    private var receiveNumber = 0L
    private val skippedMessageKeys = TreeMap<Long, ByteArray>()

    init {
        require(sessionKey.size == KEY_SIZE) { "Session key must be 32 bytes" }
        require(myId.isNotEmpty() && peerId.isNotEmpty() && myId != peerId) {
            "Participant identities are invalid"
        }
        this.myId = myId
        this.peerId = peerId
        val localId = myId.toByteArray(Charsets.UTF_8)
        val remoteId = peerId.toByteArray(Charsets.UTF_8)
        val (lowId, highId) = if (compareUnsigned(localId, remoteId) <= 0) {
            localId to remoteId
        } else {
            remoteId to localId
        }
        sessionId = hkdf(
            sessionKey,
            "SecureP2PChat-FS2-session|".toByteArray(Charsets.UTF_8) +
                lowId + byteArrayOf('|'.code.toByte()) + highId,
            SESSION_ID_SIZE
        )
        sendChainKey = hkdf(
            sessionKey,
            "SecureP2PChat-FS2|send|".toByteArray(Charsets.UTF_8) +
                localId + byteArrayOf('|'.code.toByte()) + remoteId,
            KEY_SIZE
        )
        receiveChainKey = hkdf(
            sessionKey,
            "SecureP2PChat-FS2|send|".toByteArray(Charsets.UTF_8) +
                remoteId + byteArrayOf('|'.code.toByte()) + localId,
            KEY_SIZE
        )
    }

    @Synchronized
    fun encrypt(plaintext: ByteArray): ByteArray {
        check(sendNumber <= MAX_COUNTER) {
            "FS2 message counter exhausted; establish a new session"
        }
        val header = ByteBuffer.allocate(HEADER_SIZE)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .put(sessionId)
            .putInt(sendNumber.toInt())
            .array()
        val (nextKey, messageKey) = nextChainKey(sendChainKey)
        val ciphertext = try {
            CryptoEngine.encryptBytes(plaintext, messageKey, messageContext(header, myId, peerId))
        } catch (e: Exception) {
            nextKey.fill(0)
            throw e
        } finally {
            messageKey.fill(0)
        }
        sendChainKey.fill(0)
        sendChainKey = nextKey
        sendNumber++
        return header + ciphertext
    }

    @Synchronized
    fun decrypt(payload: ByteArray): ByteArray {
        require(isPayload(payload)) { "Unsupported secure protocol frame" }
        require(payload.size >= MIN_FRAME_SIZE) { "FS2 frame too short" }
        val header = payload.copyOfRange(0, HEADER_SIZE)
        require(MessageDigest.isEqual(header.copyOfRange(MAGIC.size, MAGIC.size + SESSION_ID_SIZE), sessionId)) {
            "FS2 session mismatch; re-pair contact"
        }
        val messageNumber = ByteBuffer.wrap(header, MAGIC.size + SESSION_ID_SIZE, COUNTER_SIZE)
            .order(ByteOrder.BIG_ENDIAN)
            .int
            .toLong() and MAX_COUNTER
        val ciphertext = payload.copyOfRange(HEADER_SIZE, payload.size)
        val context = messageContext(header, peerId, myId)

        val skippedKey = skippedMessageKeys[messageNumber]
        if (skippedKey != null) {
            val plaintext = CryptoEngine.decryptBytes(ciphertext, skippedKey, context)
            skippedMessageKeys.remove(messageNumber)
            skippedKey.fill(0)
            return plaintext
        }
        require(messageNumber >= receiveNumber) {
            "FS2 replay or already-consumed message"
        }
        require(messageNumber - receiveNumber <= MAX_SKIP) {
            "FS2 skip window exceeded (received=$messageNumber, expected=$receiveNumber, max=$MAX_SKIP)"
        }

        var candidateChainKey = receiveChainKey
        var candidateNumber = receiveNumber
        val candidateSkipped = TreeMap(skippedMessageKeys)
        while (candidateNumber < messageNumber) {
            val (next, skippedKey) = nextChainKey(candidateChainKey)
            if (candidateChainKey !== receiveChainKey) candidateChainKey.fill(0)
            candidateChainKey = next
            candidateSkipped[candidateNumber] = skippedKey
            candidateNumber++
        }
        val (nextKey, messageKey) = nextChainKey(candidateChainKey)
        val plaintext = try {
            CryptoEngine.decryptBytes(ciphertext, messageKey, context)
        } catch (e: Exception) {
            if (candidateChainKey !== receiveChainKey) candidateChainKey.fill(0)
            nextKey.fill(0)
            candidateSkipped.forEach { (number, key) ->
                if (!skippedMessageKeys.containsKey(number)) key.fill(0)
            }
            throw e
        } finally {
            messageKey.fill(0)
        }

        if (candidateChainKey !== receiveChainKey) candidateChainKey.fill(0)
        candidateSkipped.remove(messageNumber)?.fill(0)
        receiveChainKey.fill(0)
        receiveChainKey = nextKey
        receiveNumber = messageNumber + 1
        skippedMessageKeys.clear()
        skippedMessageKeys.putAll(candidateSkipped)
        while (skippedMessageKeys.size > MAX_SKIP) {
            skippedMessageKeys.pollFirstEntry()?.value?.fill(0)
        }
        return plaintext
    }

    @Synchronized
    fun exportState(): ByteArray {
        val skipped = JSONObject()
        skippedMessageKeys.forEach { (number, key) ->
            skipped.put(number.toString(), encode(key))
        }
        return JSONObject()
            .put("version", STATE_VERSION)
            .put("my_id", myId)
            .put("peer_id", peerId)
            .put("session_id", encode(sessionId))
            .put("send_ck", encode(sendChainKey))
            .put("recv_ck", encode(receiveChainKey))
            .put("send_n", sendNumber)
            .put("recv_n", receiveNumber)
            .put("skipped", skipped)
            .toString()
            .toByteArray(Charsets.UTF_8)
    }

    @Synchronized
    fun destroy() {
        sendChainKey.fill(0)
        receiveChainKey.fill(0)
        skippedMessageKeys.values.forEach { it.fill(0) }
        skippedMessageKeys.clear()
    }

    companion object {
        private const val KEY_SIZE = 32
        private const val SESSION_ID_SIZE = 16
        private const val COUNTER_SIZE = 4
        private const val HEADER_SIZE = 23
        private const val MIN_FRAME_SIZE = HEADER_SIZE + 5 + 24 + 16
        private const val MAX_SKIP = 1024
        private const val MAX_COUNTER = 0xffffffffL
        private const val STATE_VERSION = 2
        private val MAGIC = "FS2".toByteArray(Charsets.US_ASCII)
        private val CHAIN_KDF_INFO =
            "SecureP2PChat-FS2-CK-v2".toByteArray(Charsets.UTF_8)

        @JvmStatic
        fun isPayload(payload: ByteArray): Boolean =
            payload.size >= MAGIC.size &&
                payload[0] == MAGIC[0] &&
                payload[1] == MAGIC[1] &&
                payload[2] == MAGIC[2]

        @JvmStatic
        fun importState(
            sessionKey: ByteArray,
            myId: String,
            peerId: String,
            rawState: ByteArray
        ): ForwardSecrecyChain {
            val data = JSONObject(String(rawState, Charsets.UTF_8))
            require(data.optInt("version", -1) == STATE_VERSION &&
                data.optString("my_id") == myId &&
                data.optString("peer_id") == peerId) {
                "FS2 state version or participant mismatch"
            }
            val chain = ForwardSecrecyChain(sessionKey, myId, peerId)
            try {
                require(MessageDigest.isEqual(decode(data.getString("session_id")), chain.sessionId)) {
                    "FS2 state belongs to another session"
                }
                val sendKey = decode(data.getString("send_ck"))
                val receiveKey = decode(data.getString("recv_ck"))
                val sendCount = data.getLong("send_n")
                val receiveCount = data.getLong("recv_n")
                require(sendKey.size == KEY_SIZE && receiveKey.size == KEY_SIZE &&
                    sendCount in 0..MAX_COUNTER + 1 && receiveCount in 0..MAX_COUNTER + 1) {
                    "FS2 state fields invalid"
                }

                val skippedJson = data.getJSONObject("skipped")
                require(skippedJson.length() <= MAX_SKIP) { "FS2 skipped-key state invalid" }
                val skipped = TreeMap<Long, ByteArray>()
                val keys = skippedJson.keys()
                while (keys.hasNext()) {
                    val number = keys.next().toLongOrNull()
                        ?: throw IllegalArgumentException("FS2 skipped-key index invalid")
                    val messageKey = decode(skippedJson.getString(number.toString()))
                    require(number in 0..MAX_COUNTER && number < receiveCount &&
                        messageKey.size == KEY_SIZE && skipped.put(number, messageKey) == null) {
                        messageKey.fill(0)
                        "FS2 skipped-key state invalid"
                    }
                }

                chain.sendChainKey.fill(0)
                chain.receiveChainKey.fill(0)
                chain.sendChainKey = sendKey
                chain.receiveChainKey = receiveKey
                chain.sendNumber = sendCount
                chain.receiveNumber = receiveCount
                chain.skippedMessageKeys.putAll(skipped)
                return chain
            } catch (e: Exception) {
                chain.destroy()
                throw e
            }
        }

        private fun messageContext(header: ByteArray, senderId: String, receiverId: String): ByteArray =
            "p2p-message-fs2|".toByteArray(Charsets.UTF_8) +
                header + identityHash(senderId) + identityHash(receiverId)

        private fun identityHash(id: String): ByteArray =
            MessageDigest.getInstance("SHA-256")
                .digest(id.toByteArray(Charsets.UTF_8))
                .copyOf(12)

        private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
            for (index in 0 until minOf(left.size, right.size)) {
                val difference = (left[index].toInt() and 0xff) - (right[index].toInt() and 0xff)
                if (difference != 0) return difference
            }
            return left.size - right.size
        }

        private fun nextChainKey(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
            val output = hkdf(chainKey, CHAIN_KDF_INFO, KEY_SIZE * 2)
            return output.copyOfRange(0, KEY_SIZE) to output.copyOfRange(KEY_SIZE, output.size)
        }

        private fun hkdf(inputKeyMaterial: ByteArray, info: ByteArray, length: Int): ByteArray {
            val generator = HKDFBytesGenerator(SHA256Digest())
            generator.init(HKDFParameters(inputKeyMaterial, null, info))
            return ByteArray(length).also { generator.generateBytes(it, 0, length) }
        }

        private fun encode(bytes: ByteArray): String =
            Base64.toBase64String(bytes)

        private fun decode(value: String): ByteArray {
            val decoded = Base64.decode(value)
            require(encode(decoded) == value) { "Invalid FS2 state encoding" }
            return decoded
        }
    }
}
