package com.example.securep2p

import com.example.securep2p.crypto.CryptoEngine
import com.example.securep2p.protocol.Constants
import com.example.securep2p.protocol.Protocol
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.digests.SHA256Digest
import org.junit.Test
import org.junit.Assert.*

class ExampleUnitTest {

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testArgon2() {
        val salt = ByteArray(16) { 1 }
        val password = "TestPassword123!"
        val derived = CryptoEngine.deriveKeyFromPassword(password, salt)
        assertEquals("5b283768f43c70d579392c66beff46af5d494fd1bc4016cc34f57b39b355774e", derived.toHexString())
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testEd25519() {
        val seed = ByteArray(32) { 0x30 }
        val priv = Ed25519PrivateKeyParameters(seed, 0)
        val pub = priv.generatePublicKey()
        assertEquals("1ba4075b77c9e3fb3ecde15cdaf5221f3c10373e623f7b0e1ef76366b0af7137", pub.encoded.toHexString())

        val msg = "TestCanonicalSignatureString".toByteArray(Charsets.UTF_8)
        val sig = CryptoEngine.sign(priv.encoded, msg)
        assertEquals("3aeead56bc496b5bb71c25517afefc521a368a8b495fea43ab7ad6a61300ef77cfa925b4638eb35169af47a95f1a34d795a27b2c6e487782af1f0e41605c5a00", sig.toHexString())
        assertTrue(CryptoEngine.verify(pub.encoded, msg, sig))
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testKeyExchangeAndSessionKey() {
        val sk1Bytes = ByteArray(32) { 0x10 }
        val sk2Bytes = ByteArray(32) { 0x20 }
        val priv1 = X25519PrivateKeyParameters(sk1Bytes, 0)
        val priv2 = X25519PrivateKeyParameters(sk2Bytes, 0)
        val pub1 = priv1.generatePublicKey()
        val pub2 = priv2.generatePublicKey()

        assertEquals("781faab908430150daccdd6f9d6c5086e34f73a93ebbaa271765e5036edfc519", pub1.encoded.toHexString())
        assertEquals("06453fcd9cef5a1f53acc4f942104c0c8e9e27d5c7b37f5507cdcd1628105963", pub2.encoded.toHexString())

        val sessionKey1 = CryptoEngine.performKeyExchange(sk1Bytes, pub2.encoded)
        val sessionKey2 = CryptoEngine.performKeyExchange(sk2Bytes, pub1.encoded)

        assertEquals("cab101ff40f1f1eef26278bd9f411f7598598db9ad6f70568e1356a108c681fa", sessionKey1.toHexString())
        assertEquals(sessionKey1.toHexString(), sessionKey2.toHexString())
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testDecryptPythonMessage() {
        val sessionKey = "cab101ff40f1f1eef26278bd9f411f7598598db9ad6f70568e1356a108c681fa".hexToByteArray()
        val encHex = "5350433202d2996e493f46e6fc81cc702c4d5195fc79acd89bc5cd50fbb549f2f20a8eeb02bc5d35ab97f6b356eb1ea77868a957a51353319a08c0ac417632951bd6"
        val ciphertext = encHex.hexToByteArray()

        val plain = CryptoEngine.decryptMessage(sessionKey, ciphertext).toString(Charsets.UTF_8)
        assertEquals("Salut din Python P2P!", plain)
    }

    @Test
    fun testProtocolPackingAndUnpacking() {
        val payload = "Hello P2P Relay".toByteArray(Charsets.UTF_8)
        val packed = Protocol.packMessage(Constants.MSG_TEXT, payload)
        val (type, unpacked) = Protocol.unpackMessage(packed)
        assertEquals(Constants.MSG_TEXT, type)
        assertArrayEquals(payload, unpacked)
    }

    @Test
    fun testKeyExchangeHandshake() {
        val kp = CryptoEngine.generateX25519KeyPair()
        val signKp = CryptoEngine.deriveEd25519KeyPair(kp.privateKey)
        val kexPayload = Protocol.createKeyExchange(
            publicKey = kp.publicKey,
            deviceId = "dev-android-test",
            displayName = "AndroidUser",
            signingPrivateKey = signKp.privateKey,
            verifyKey = signKp.verifyKey
        )

        assertTrue(Protocol.verifyKeyExchange(kexPayload))
        val parsed = Protocol.parseKeyExchange(kexPayload)
        assertEquals(Constants.PROTOCOL_VERSION, parsed.version)
        assertEquals("dev-android-test", parsed.deviceId)
        assertArrayEquals(kp.publicKey, parsed.publicKey)
        assertArrayEquals(signKp.verifyKey, parsed.verifyKey)
    }

    @Test
    fun testFileTransferProtocols() {
        val tid = "test_transfer_12"
        val filename = "secure_doc.pdf"
        val size = 1048576L
        val chunks = 16

        val start = Protocol.createFileStart(tid, filename, size, chunks)
        val parsedStart = Protocol.parseFileStart(start)
        assertEquals(tid, parsedStart.transferId)
        assertEquals(filename, parsedStart.filename)
        assertEquals(size, parsedStart.fileSize)
        assertEquals(chunks, parsedStart.totalChunks)

        val chunkData = ByteArray(1024) { 0x42 }
        val chunk = Protocol.createFileChunk(tid, 5, chunkData)
        val parsedChunk = Protocol.parseFileChunk(chunk)
        assertEquals(tid, parsedChunk.transferId)
        assertEquals(5, parsedChunk.chunkIndex)
        assertArrayEquals(chunkData, parsedChunk.encryptedData)

        val end = Protocol.createFileEnd(tid)
        val parsedEnd = Protocol.parseFileEnd(end)
        assertEquals(tid, parsedEnd)
    }

    @Test
    fun testEndToEndEncryptionBetweenTwoPeers() {
        val aliceX = CryptoEngine.generateX25519KeyPair()
        val bobX = CryptoEngine.generateX25519KeyPair()

        val aliceSession = CryptoEngine.performKeyExchange(aliceX.privateKey, bobX.publicKey)
        val bobSession = CryptoEngine.performKeyExchange(bobX.privateKey, aliceX.publicKey)

        assertArrayEquals(aliceSession, bobSession)

        val secretMsg = "Mesaj ultra confidențial transmis prin releu P2P!"
        val encrypted = CryptoEngine.encryptMessage(aliceSession, secretMsg.toByteArray(Charsets.UTF_8))
        val decrypted = CryptoEngine.decryptMessage(bobSession, encrypted)

        assertEquals(secretMsg, String(decrypted, Charsets.UTF_8))

        val fpAlice = CryptoEngine.publicKeyFingerprint(aliceX.publicKey)
        assertTrue(fpAlice.length >= 48)
    }
}
