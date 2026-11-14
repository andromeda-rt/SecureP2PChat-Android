package com.example.securep2p.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.TreeMap

/** Per-sender FS chain derived from a group epoch secret shared out-of-band via pairwise FS2. */
class GroupSenderKeyChain(
    epochSecret: ByteArray,
    val groupId: String,
    val epoch: Long,
    val senderId: String
) : AutoCloseable {
    private var chainKey: ByteArray
    private var nextNumber = 0L
    private val skipped = TreeMap<Long, ByteArray>()

    init {
        require(epochSecret.size == KEY_SIZE && groupId.isNotBlank() && senderId.isNotBlank())
        require(epoch >= 0)
        chainKey = hkdf(
            epochSecret,
            "SecureP2PChat-GSK-v1|$groupId|$epoch|$senderId".toByteArray(Charsets.UTF_8),
            KEY_SIZE
        )
    }

    @Synchronized
    fun encrypt(plaintext: ByteArray): ByteArray {
        check(nextNumber <= MAX_COUNTER) { "Group sender counter exhausted" }
        val header = ByteBuffer.allocate(HEADER_SIZE)
            .order(ByteOrder.BIG_ENDIAN)
            .put(MAGIC)
            .putLong(epoch)
            .putInt(nextNumber.toInt())
            .array()
        val (nextKey, messageKey) = nextChainKey(chainKey)
        val context = messageContext(header)
        val ciphertext = try {
            CryptoEngine.encryptBytes(plaintext, messageKey, context)
        } catch (e: Exception) {
            nextKey.fill(0)
            throw e
        } finally {
            messageKey.fill(0)
        }
        chainKey.fill(0)
        chainKey = nextKey
        nextNumber++
        return header + ciphertext
    }

    @Synchronized
    fun decrypt(frame: ByteArray): ByteArray {
        require(frame.size >= MIN_FRAME_SIZE && frame.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
            "Invalid group sender-key frame"
        }
        val header = frame.copyOfRange(0, HEADER_SIZE)
        val buffer = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        buffer.position(MAGIC.size)
        require(buffer.long == epoch) { "Group epoch mismatch" }
        val number = buffer.int.toLong() and MAX_COUNTER
        val ciphertext = frame.copyOfRange(HEADER_SIZE, frame.size)
        val context = messageContext(header)

        skipped[number]?.let { key ->
            val plaintext = CryptoEngine.decryptBytes(ciphertext, key, context)
            skipped.remove(number)
            key.fill(0)
            return plaintext
        }
        require(number >= nextNumber) { "Group message replay" }
        require(number - nextNumber <= MAX_SKIP) { "Group message skip window exceeded" }

        var candidate = chainKey
        var index = nextNumber
        val candidateSkipped = TreeMap(skipped)
        while (index < number) {
            val (next, messageKey) = nextChainKey(candidate)
            if (candidate !== chainKey) candidate.fill(0)
            candidate = next
            candidateSkipped[index] = messageKey
            index++
        }
        val (nextKey, messageKey) = nextChainKey(candidate)
        val plaintext = try {
            CryptoEngine.decryptBytes(ciphertext, messageKey, context)
        } catch (e: Exception) {
            if (candidate !== chainKey) candidate.fill(0)
            nextKey.fill(0)
            candidateSkipped.forEach { (keyNumber, key) ->
                if (!skipped.containsKey(keyNumber)) key.fill(0)
            }
            throw e
        } finally {
            messageKey.fill(0)
        }
        if (candidate !== chainKey) candidate.fill(0)
        candidateSkipped.remove(number)?.fill(0)
        chainKey.fill(0)
        chainKey = nextKey
        nextNumber = number + 1
        skipped.clear()
        skipped.putAll(candidateSkipped)
        while (skipped.size > MAX_SKIP) skipped.pollFirstEntry()?.value?.fill(0)
        return plaintext
    }

    @Synchronized
    fun exportState(): ByteArray {
        val skippedJson = JSONObject()
        skipped.forEach { (number, key) -> skippedJson.put(number.toString(), encode(key)) }
        return JSONObject()
            .put("version", STATE_VERSION)
            .put("group_id", groupId)
            .put("epoch", epoch)
            .put("sender_id", senderId)
            .put("chain_key", encode(chainKey))
            .put("next_number", nextNumber)
            .put("skipped", skippedJson)
            .toString()
            .toByteArray(Charsets.UTF_8)
    }

    @Synchronized
    fun destroy() {
        chainKey.fill(0)
        skipped.values.forEach { it.fill(0) }
        skipped.clear()
    }

    override fun close() = destroy()

    private fun messageContext(header: ByteArray): ByteArray =
        "group-message-v1|".toByteArray(Charsets.UTF_8) +
            groupId.toByteArray(Charsets.UTF_8) +
            byteArrayOf(0) + senderId.toByteArray(Charsets.UTF_8) + header

    companion object {
        private const val KEY_SIZE = 32
        private const val HEADER_SIZE = 16
        private const val MIN_FRAME_SIZE = HEADER_SIZE + 5 + 24 + 16
        private const val MAX_SKIP = 1024
        private const val MAX_COUNTER = 0xffffffffL
        private const val STATE_VERSION = 1
        private val MAGIC = "GSK1".toByteArray(Charsets.US_ASCII)
        private val CHAIN_INFO = "SecureP2PChat-GSK-CK-v1".toByteArray(Charsets.UTF_8)

        private fun nextChainKey(key: ByteArray): Pair<ByteArray, ByteArray> {
            val output = hkdf(key, CHAIN_INFO, KEY_SIZE * 2)
            return output.copyOfRange(0, KEY_SIZE) to output.copyOfRange(KEY_SIZE, output.size)
        }

        private fun hkdf(input: ByteArray, info: ByteArray, length: Int): ByteArray {
            val generator = HKDFBytesGenerator(SHA256Digest())
            generator.init(HKDFParameters(input, null, info))
            return ByteArray(length).also { generator.generateBytes(it, 0, length) }
        }

        private fun encode(bytes: ByteArray): String =
            org.bouncycastle.util.encoders.Base64.toBase64String(bytes)

        @JvmStatic
        fun importState(epochSecret: ByteArray, rawState: ByteArray): GroupSenderKeyChain {
            val data = JSONObject(String(rawState, Charsets.UTF_8))
            require(data.optInt("version", -1) == STATE_VERSION)
            val chain = GroupSenderKeyChain(
                epochSecret,
                data.getString("group_id"),
                data.getLong("epoch"),
                data.getString("sender_id")
            )
            try {
                val restoredKey = org.bouncycastle.util.encoders.Base64.decode(data.getString("chain_key"))
                val restoredNumber = data.getLong("next_number")
                val skippedData = data.getJSONObject("skipped")
                require(restoredKey.size == KEY_SIZE && restoredNumber in 0..MAX_COUNTER + 1)
                require(skippedData.length() <= MAX_SKIP)
                val restoredSkipped = TreeMap<Long, ByteArray>()
                val keys = skippedData.keys()
                while (keys.hasNext()) {
                    val keyNumber = keys.next().toLongOrNull()
                        ?: throw IllegalArgumentException("Invalid skipped group-key index")
                    val messageKey = org.bouncycastle.util.encoders.Base64.decode(
                        skippedData.getString(keyNumber.toString())
                    )
                    require(keyNumber in 0 until restoredNumber &&
                        keyNumber <= MAX_COUNTER && messageKey.size == KEY_SIZE)
                    restoredSkipped[keyNumber] = messageKey
                }
                chain.chainKey.fill(0)
                chain.chainKey = restoredKey
                chain.nextNumber = restoredNumber
                chain.skipped.putAll(restoredSkipped)
                return chain
            } catch (e: Exception) {
                chain.destroy()
                throw e
            }
        }

        @JvmStatic
        fun isFrame(frame: ByteArray): Boolean =
            frame.size >= MAGIC.size && MessageDigest.isEqual(frame.copyOfRange(0, MAGIC.size), MAGIC)
    }
}
