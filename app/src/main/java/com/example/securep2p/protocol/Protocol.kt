package com.example.securep2p.protocol

import com.example.securep2p.crypto.CryptoEngine
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class KeyExchangeData(
    val version: Int,
    val publicKey: ByteArray,
    val deviceId: String,
    val displayName: String,
    val verifyKey: ByteArray,
    val signature: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is KeyExchangeData) return false
        return version == other.version &&
                publicKey.contentEquals(other.publicKey) &&
                deviceId == other.deviceId &&
                displayName == other.displayName &&
                verifyKey.contentEquals(other.verifyKey) &&
                signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + publicKey.contentHashCode()
        result = 31 * result + deviceId.hashCode()
        result = 31 * result + displayName.hashCode()
        result = 31 * result + verifyKey.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

data class FileStartData(
    val transferId: String,
    val filename: String,
    val fileSize: Long,
    val totalChunks: Int
)

data class FileChunkData(
    val transferId: String,
    val chunkIndex: Int,
    val encryptedData: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FileChunkData) return false
        return transferId == other.transferId &&
                chunkIndex == other.chunkIndex &&
                encryptedData.contentEquals(other.encryptedData)
    }

    override fun hashCode(): Int {
        var result = transferId.hashCode()
        result = 31 * result + chunkIndex
        result = 31 * result + encryptedData.contentHashCode()
        return result
    }
}

object Protocol {
    fun packMessage(msgType: Byte, payload: ByteArray = ByteArray(0)): ByteArray {
        val length = 1 + payload.size
        val bb = ByteBuffer.allocate(4 + 1 + payload.size).order(ByteOrder.BIG_ENDIAN)
        bb.putInt(length)
        bb.put(msgType)
        bb.put(payload)
        return bb.array()
    }

    fun unpackMessage(data: ByteArray): Pair<Byte, ByteArray> {
        if (data.size < 5) throw IllegalArgumentException("Mesaj prea scurt")
        val bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val length = bb.getInt()
        if (length < 1 || length > 20 * 1024 * 1024) throw IllegalArgumentException("Lungime invalidă")
        if (data.size < 4 + length) throw IllegalArgumentException("Date incomplete")
        val msgType = bb.get()
        val payload = ByteArray(length - 1)
        bb.get(payload)
        return Pair(msgType, payload)
    }

    fun keyExchangeTranscript(
        publicKey: ByteArray,
        deviceId: String,
        displayName: String,
        verifyKey: ByteArray
    ): ByteArray {
        require(publicKey.size == 32 && verifyKey.size == 32) { "Cheie publică invalidă" }
        val idBytes = deviceId.toByteArray(Charsets.UTF_8)
        val nameBytes = displayName.toByteArray(Charsets.UTF_8)
        require(idBytes.isNotEmpty() && idBytes.size <= 256 && nameBytes.size <= 512) { "ID/nume invalid" }

        val prefix = "SecureP2PChat-key-exchange-v1\u0000".toByteArray(Charsets.ISO_8859_1)
        val out = ByteArrayOutputStream()
        out.write(prefix)
        out.write(Constants.PROTOCOL_VERSION)
        out.write(publicKey)
        out.write(byteArrayOf(((idBytes.size ushr 8) and 0xff).toByte(), (idBytes.size and 0xff).toByte()))
        out.write(idBytes)
        out.write(byteArrayOf(((nameBytes.size ushr 8) and 0xff).toByte(), (nameBytes.size and 0xff).toByte()))
        out.write(nameBytes)
        out.write(verifyKey)
        return out.toByteArray()
    }

    fun createKeyExchange(
        publicKey: ByteArray,
        deviceId: String,
        displayName: String,
        signingPrivateKey: ByteArray,
        verifyKey: ByteArray
    ): ByteArray {
        val wireName = "" // Privacy: wire name is always empty in desktop protocol
        val transcript = keyExchangeTranscript(publicKey, deviceId, wireName, verifyKey)
        val signature = CryptoEngine.sign(signingPrivateKey, transcript)

        val idBytes = deviceId.toByteArray(Charsets.UTF_8)
        val nameBytes = wireName.toByteArray(Charsets.UTF_8)

        val out = ByteArrayOutputStream()
        out.write(Constants.PROTOCOL_VERSION)
        out.write(publicKey)
        out.write(byteArrayOf(((idBytes.size ushr 8) and 0xff).toByte(), (idBytes.size and 0xff).toByte()))
        out.write(idBytes)
        out.write(byteArrayOf(((nameBytes.size ushr 8) and 0xff).toByte(), (nameBytes.size and 0xff).toByte()))
        out.write(nameBytes)
        out.write(verifyKey)
        out.write(signature)
        return out.toByteArray()
    }

    fun parseKeyExchange(payload: ByteArray): KeyExchangeData {
        if (payload.size < 1 + 32 + 2 + 1 + 2 + 32 + 64) {
            throw IllegalArgumentException("Key exchange prea scurt")
        }
        val version = payload[0].toInt() and 0xff
        if (version != Constants.PROTOCOL_VERSION) {
            throw IllegalArgumentException("Versiune de protocol incompatibilă: $version")
        }
        val publicKey = payload.copyOfRange(1, 33)
        var pos = 33

        val idLen = ((payload[pos].toInt() and 0xff) shl 8) or (payload[pos + 1].toInt() and 0xff)
        pos += 2
        if (idLen < 1 || idLen > 256 || pos + idLen + 2 > payload.size) {
            throw IllegalArgumentException("Lungime ID invalidă")
        }
        val deviceId = String(payload, pos, idLen, Charsets.UTF_8)
        pos += idLen

        val nameLen = ((payload[pos].toInt() and 0xff) shl 8) or (payload[pos + 1].toInt() and 0xff)
        pos += 2
        if (nameLen > 512 || pos + nameLen + 96 != payload.size) {
            throw IllegalArgumentException("Lungime nume/semnătură invalidă")
        }
        val displayName = String(payload, pos, nameLen, Charsets.UTF_8)
        pos += nameLen

        val verifyKey = payload.copyOfRange(pos, pos + 32)
        pos += 32
        val signature = payload.copyOfRange(pos, pos + 64)
        return KeyExchangeData(version, publicKey, deviceId, displayName, verifyKey, signature)
    }

    fun verifyKeyExchange(payload: ByteArray): Boolean {
        return try {
            val data = parseKeyExchange(payload)
            val transcript = keyExchangeTranscript(data.publicKey, data.deviceId, data.displayName, data.verifyKey)
            CryptoEngine.verify(data.verifyKey, transcript, data.signature)
        } catch (e: Exception) {
            false
        }
    }

    private fun fixedTransferId(transferId: String): ByteArray {
        val b = transferId.toByteArray(Charsets.UTF_8)
        val res = ByteArray(16)
        val copyLen = minOf(b.size, 16)
        System.arraycopy(b, 0, res, 0, copyLen)
        return res
    }

    private fun parseTransferId(bytes: ByteArray, offset: Int = 0): String {
        var end = offset + 16
        while (end > offset && bytes[end - 1] == 0.toByte()) {
            end--
        }
        return String(bytes, offset, end - offset, Charsets.UTF_8)
    }

    fun createFileStart(transferId: String, filename: String, fileSize: Long, totalChunks: Int): ByteArray {
        val tid = fixedTransferId(transferId)
        val nameBytes = filename.toByteArray(Charsets.UTF_8)
        val bb = ByteBuffer.allocate(16 + 8 + 4 + 2 + nameBytes.size).order(ByteOrder.BIG_ENDIAN)
        bb.put(tid)
        bb.putLong(fileSize)
        bb.putInt(totalChunks)
        bb.putShort(nameBytes.size.toShort())
        bb.put(nameBytes)
        return bb.array()
    }

    fun parseFileStart(payload: ByteArray): FileStartData {
        if (payload.size < 30) throw IllegalArgumentException("FILE_START prea scurt")
        val tid = parseTransferId(payload, 0)
        val bb = ByteBuffer.wrap(payload, 16, payload.size - 16).order(ByteOrder.BIG_ENDIAN)
        val fileSize = bb.getLong()
        val totalChunks = bb.getInt()
        val nameLen = bb.getShort().toInt() and 0xffff
        val nameBytes = ByteArray(nameLen)
        bb.get(nameBytes)
        val filename = String(nameBytes, Charsets.UTF_8)
        return FileStartData(tid, filename, fileSize, totalChunks)
    }

    fun createFileChunk(transferId: String, chunkIndex: Int, encryptedData: ByteArray): ByteArray {
        val tid = fixedTransferId(transferId)
        val bb = ByteBuffer.allocate(16 + 4 + encryptedData.size).order(ByteOrder.BIG_ENDIAN)
        bb.put(tid)
        bb.putInt(chunkIndex)
        bb.put(encryptedData)
        return bb.array()
    }

    fun parseFileChunk(payload: ByteArray): FileChunkData {
        if (payload.size < 20) throw IllegalArgumentException("FILE_CHUNK prea scurt")
        val tid = parseTransferId(payload, 0)
        val bb = ByteBuffer.wrap(payload, 16, 4).order(ByteOrder.BIG_ENDIAN)
        val chunkIndex = bb.getInt()
        val data = payload.copyOfRange(20, payload.size)
        return FileChunkData(tid, chunkIndex, data)
    }

    fun createFileEnd(transferId: String): ByteArray {
        return fixedTransferId(transferId)
    }

    fun parseFileEnd(payload: ByteArray): String {
        return parseTransferId(payload, 0)
    }
}
