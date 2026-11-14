package com.example.securep2p.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.MessageDigest
import java.security.SecureRandom

data class X25519KeyPair(val privateKey: ByteArray, val publicKey: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X25519KeyPair) return false
        return privateKey.contentEquals(other.privateKey) && publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int = 31 * privateKey.contentHashCode() + publicKey.contentHashCode()
}

data class Ed25519KeyPair(val privateKey: ByteArray, val verifyKey: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Ed25519KeyPair) return false
        return privateKey.contentEquals(other.privateKey) && verifyKey.contentEquals(other.verifyKey)
    }

    override fun hashCode(): Int = 31 * privateKey.contentHashCode() + verifyKey.contentHashCode()
}

object CryptoEngine {
    private val secureRandom = SecureRandom()
    private val ENVELOPE_MAGIC = "SPC2".toByteArray(Charsets.US_ASCII)
    private const val ENVELOPE_VERSION: Byte = 2
    private val DEFAULT_CONTEXT = "storage".toByteArray(Charsets.UTF_8)
    val P2P_MESSAGE_CONTEXT = "p2p-message".toByteArray(Charsets.UTF_8)

    fun deriveKeyFromPassword(password: String, salt: ByteArray): ByteArray {
        System.gc()
        val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(3)
            .withMemoryAsKB(65536)
            .withParallelism(4)
            .withSalt(salt)
        val generator = Argon2BytesGenerator()
        generator.init(builder.build())
        val result = ByteArray(32)
        generator.generateBytes(password.toByteArray(Charsets.UTF_8), result, 0, result.size)
        System.gc()
        return result
    }

    fun generateX25519KeyPair(): X25519KeyPair {
        val privBytes = ByteArray(32)
        secureRandom.nextBytes(privBytes)
        val priv = X25519PrivateKeyParameters(privBytes, 0)
        val pub = priv.generatePublicKey()
        return X25519KeyPair(priv.encoded, pub.encoded)
    }

    fun deriveEd25519KeyPair(x25519PrivBytes: ByteArray): Ed25519KeyPair {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("SecureP2PChat-SignSeed-v1".toByteArray(Charsets.UTF_8))
        md.update(x25519PrivBytes)
        val seed = md.digest()
        val priv = Ed25519PrivateKeyParameters(seed, 0)
        val pub = priv.generatePublicKey()
        return Ed25519KeyPair(priv.encoded, pub.encoded)
    }

    fun performKeyExchange(privateKeyBytes: ByteArray, peerPublicKeyBytes: ByteArray): ByteArray {
        val priv = X25519PrivateKeyParameters(privateKeyBytes, 0)
        val pub = X25519PublicKeyParameters(peerPublicKeyBytes, 0)
        val agreement = X25519Agreement()
        agreement.init(priv)
        val sharedPoint = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(pub, sharedPoint, 0)

        val beforenm = hsalsa20(ByteArray(16), sharedPoint)

        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(beforenm, null, "SecureP2PChat-SessionKey-v1".toByteArray(Charsets.UTF_8)))
        val sessionKey = ByteArray(32)
        hkdf.generateBytes(sessionKey, 0, 32)
        return sessionKey
    }

    fun rawKeyAgreement(privateKeyBytes: ByteArray, peerPublicKeyBytes: ByteArray): ByteArray {
        val priv = X25519PrivateKeyParameters(privateKeyBytes, 0)
        val pub = X25519PublicKeyParameters(peerPublicKeyBytes, 0)
        val agreement = X25519Agreement()
        agreement.init(priv)
        val sharedPoint = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(pub, sharedPoint, 0)
        return sharedPoint
    }

    private fun envelopeAad(context: ByteArray): ByteArray {
        val prefix = "SecureP2PChat\u0000AEAD\u0000v2\u0000".toByteArray(Charsets.UTF_8)
        val aad = ByteArray(prefix.size + context.size)
        System.arraycopy(prefix, 0, aad, 0, prefix.size)
        System.arraycopy(context, 0, aad, prefix.size, context.size)
        return aad
    }

    fun encryptBytes(plaintext: ByteArray, key: ByteArray, context: ByteArray = DEFAULT_CONTEXT): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes" }
        val nonce = ByteArray(24)
        secureRandom.nextBytes(nonce)

        val subkey = hchacha20(key, nonce.copyOfRange(0, 16))
        val subnonce = ByteArray(12)
        System.arraycopy(nonce, 16, subnonce, 4, 8)

        val aad = envelopeAad(context)
        val cipher = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(subkey), 128, subnonce, aad))

        val encrypted = ByteArray(cipher.getOutputSize(plaintext.size))
        val len = cipher.processBytes(plaintext, 0, plaintext.size, encrypted, 0)
        val finalLen = len + cipher.doFinal(encrypted, len)

        val result = ByteArray(ENVELOPE_MAGIC.size + 1 + nonce.size + finalLen)
        var offset = 0
        System.arraycopy(ENVELOPE_MAGIC, 0, result, offset, ENVELOPE_MAGIC.size); offset += ENVELOPE_MAGIC.size
        result[offset++] = ENVELOPE_VERSION
        System.arraycopy(nonce, 0, result, offset, nonce.size); offset += nonce.size
        System.arraycopy(encrypted, 0, result, offset, finalLen)
        return result
    }

    fun decryptBytes(ciphertext: ByteArray, key: ByteArray, context: ByteArray = DEFAULT_CONTEXT): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes" }
        val minLen = ENVELOPE_MAGIC.size + 1 + 24 + 16
        if (ciphertext.size < minLen ||
            ciphertext[0] != ENVELOPE_MAGIC[0] ||
            ciphertext[1] != ENVELOPE_MAGIC[1] ||
            ciphertext[2] != ENVELOPE_MAGIC[2] ||
            ciphertext[3] != ENVELOPE_MAGIC[3] ||
            ciphertext[4] != ENVELOPE_VERSION
        ) {
            throw IllegalArgumentException("Invalid envelope or unsupported version")
        }

        var offset = 5
        val nonce = ciphertext.copyOfRange(offset, offset + 24); offset += 24
        val encryptedData = ciphertext.copyOfRange(offset, ciphertext.size)

        val subkey = hchacha20(key, nonce.copyOfRange(0, 16))
        val subnonce = ByteArray(12)
        System.arraycopy(nonce, 16, subnonce, 4, 8)

        val aad = envelopeAad(context)
        val cipher = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(subkey), 128, subnonce, aad))

        val decrypted = ByteArray(cipher.getOutputSize(encryptedData.size))
        val len = cipher.processBytes(encryptedData, 0, encryptedData.size, decrypted, 0)
        val finalLen = len + cipher.doFinal(decrypted, len)
        return decrypted.copyOf(finalLen)
    }

    fun encryptMessage(sessionKey: ByteArray, plaintext: ByteArray): ByteArray {
        return encryptBytes(plaintext, sessionKey, P2P_MESSAGE_CONTEXT)
    }

    fun decryptMessage(sessionKey: ByteArray, ciphertext: ByteArray): ByteArray {
        return decryptBytes(ciphertext, sessionKey, P2P_MESSAGE_CONTEXT)
    }

    fun sign(privKeyBytes: ByteArray, message: ByteArray): ByteArray {
        val priv = Ed25519PrivateKeyParameters(privKeyBytes, 0)
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun verify(verifyKeyBytes: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        return try {
            val pub = Ed25519PublicKeyParameters(verifyKeyBytes, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, pub)
            verifier.update(message, 0, message.size)
            verifier.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun publicKeyFingerprint(pubKey: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        val h = md.digest(pubKey).toHexString().uppercase()
        val groups = mutableListOf<String>()
        for (i in 0 until minOf(48, h.length) step 4) {
            groups.add(h.substring(i, minOf(i + 4, h.length)))
        }
        return groups.joinToString(" ")
    }

    private fun hsalsa20(input: ByteArray, key: ByteArray): ByteArray {
        val c = intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
        fun load32LE(b: ByteArray, offset: Int): Int {
            return (b[offset].toInt() and 0xff) or
                    ((b[offset + 1].toInt() and 0xff) shl 8) or
                    ((b[offset + 2].toInt() and 0xff) shl 16) or
                    ((b[offset + 3].toInt() and 0xff) shl 24)
        }
        fun rotl(v: Int, shift: Int): Int = (v shl shift) or (v ushr (32 - shift))

        val x = IntArray(16)
        x[0] = c[0]
        x[1] = load32LE(key, 0)
        x[2] = load32LE(key, 4)
        x[3] = load32LE(key, 8)
        x[4] = load32LE(key, 12)
        x[5] = c[1]
        x[6] = load32LE(input, 0)
        x[7] = load32LE(input, 4)
        x[8] = load32LE(input, 8)
        x[9] = load32LE(input, 12)
        x[10] = c[2]
        x[11] = load32LE(key, 16)
        x[12] = load32LE(key, 20)
        x[13] = load32LE(key, 24)
        x[14] = load32LE(key, 28)
        x[15] = c[3]

        repeat(10) {
            x[4] = x[4] xor rotl(x[0] + x[12], 7)
            x[8] = x[8] xor rotl(x[4] + x[0], 9)
            x[12] = x[12] xor rotl(x[8] + x[4], 13)
            x[0] = x[0] xor rotl(x[12] + x[8], 18)

            x[9] = x[9] xor rotl(x[5] + x[1], 7)
            x[13] = x[13] xor rotl(x[9] + x[5], 9)
            x[1] = x[1] xor rotl(x[13] + x[9], 13)
            x[5] = x[5] xor rotl(x[1] + x[13], 18)

            x[14] = x[14] xor rotl(x[10] + x[6], 7)
            x[2] = x[2] xor rotl(x[14] + x[10], 9)
            x[6] = x[6] xor rotl(x[2] + x[14], 13)
            x[10] = x[10] xor rotl(x[6] + x[2], 18)

            x[3] = x[3] xor rotl(x[15] + x[11], 7)
            x[7] = x[7] xor rotl(x[3] + x[15], 9)
            x[11] = x[11] xor rotl(x[7] + x[3], 13)
            x[15] = x[15] xor rotl(x[11] + x[7], 18)

            x[1] = x[1] xor rotl(x[0] + x[3], 7)
            x[2] = x[2] xor rotl(x[1] + x[0], 9)
            x[3] = x[3] xor rotl(x[2] + x[1], 13)
            x[0] = x[0] xor rotl(x[3] + x[2], 18)

            x[6] = x[6] xor rotl(x[5] + x[4], 7)
            x[7] = x[7] xor rotl(x[6] + x[5], 9)
            x[4] = x[4] xor rotl(x[7] + x[6], 13)
            x[5] = x[5] xor rotl(x[4] + x[7], 18)

            x[11] = x[11] xor rotl(x[10] + x[9], 7)
            x[8] = x[8] xor rotl(x[11] + x[10], 9)
            x[9] = x[9] xor rotl(x[8] + x[11], 13)
            x[10] = x[10] xor rotl(x[9] + x[8], 18)

            x[12] = x[12] xor rotl(x[15] + x[14], 7)
            x[13] = x[13] xor rotl(x[12] + x[15], 9)
            x[14] = x[14] xor rotl(x[13] + x[12], 13)
            x[15] = x[15] xor rotl(x[14] + x[13], 18)
        }

        fun store32LE(v: Int, b: ByteArray, offset: Int) {
            b[offset] = (v and 0xff).toByte()
            b[offset + 1] = ((v ushr 8) and 0xff).toByte()
            b[offset + 2] = ((v ushr 16) and 0xff).toByte()
            b[offset + 3] = ((v ushr 24) and 0xff).toByte()
        }

        val out = ByteArray(32)
        store32LE(x[0], out, 0)
        store32LE(x[5], out, 4)
        store32LE(x[10], out, 8)
        store32LE(x[15], out, 12)
        store32LE(x[6], out, 16)
        store32LE(x[7], out, 20)
        store32LE(x[8], out, 24)
        store32LE(x[9], out, 28)
        return out
    }

    private fun hchacha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        val c = intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)
        fun load32LE(b: ByteArray, offset: Int): Int {
            return (b[offset].toInt() and 0xff) or
                    ((b[offset + 1].toInt() and 0xff) shl 8) or
                    ((b[offset + 2].toInt() and 0xff) shl 16) or
                    ((b[offset + 3].toInt() and 0xff) shl 24)
        }
        fun rotl(v: Int, shift: Int): Int = (v shl shift) or (v ushr (32 - shift))

        fun qr(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
            x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16)
            x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
            x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8)
            x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
        }

        val x = IntArray(16)
        x[0] = c[0]; x[1] = c[1]; x[2] = c[2]; x[3] = c[3]
        for (i in 0 until 8) {
            x[4 + i] = load32LE(key, i * 4)
        }
        for (i in 0 until 4) {
            x[12 + i] = load32LE(nonce16, i * 4)
        }

        repeat(10) {
            qr(x, 0, 4, 8, 12)
            qr(x, 1, 5, 9, 13)
            qr(x, 2, 6, 10, 14)
            qr(x, 3, 7, 11, 15)

            qr(x, 0, 5, 10, 15)
            qr(x, 1, 6, 11, 12)
            qr(x, 2, 7, 8, 13)
            qr(x, 3, 4, 9, 14)
        }

        fun store32LE(v: Int, b: ByteArray, offset: Int) {
            b[offset] = (v and 0xff).toByte()
            b[offset + 1] = ((v ushr 8) and 0xff).toByte()
            b[offset + 2] = ((v ushr 16) and 0xff).toByte()
            b[offset + 3] = ((v ushr 24) and 0xff).toByte()
        }

        val out = ByteArray(32)
        store32LE(x[0], out, 0)
        store32LE(x[1], out, 4)
        store32LE(x[2], out, 8)
        store32LE(x[3], out, 12)
        store32LE(x[12], out, 16)
        store32LE(x[13], out, 20)
        store32LE(x[14], out, 24)
        store32LE(x[15], out, 28)
        return out
    }
}
