package com.example.securep2p

import com.example.securep2p.crypto.CryptoEngine
import com.example.securep2p.crypto.ForwardSecrecyChain
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class ForwardSecrecyChainTest {
    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun decryptsReferencePythonFs2Payload() {
        val sessionKey = ByteArray(32) { it.toByte() }
        val payload =
            "465332a6a17fe35cd98eabea718464c4c3e599000000005350433202982539debf12b79f5add424ef4daa5487b42d2b8e708b145f9c19fdaa98411c028940dc95b34abac332ba873f037711fc5d12f22887cee5ff73e"
                .hexToByteArray()
        val receiver = ForwardSecrecyChain(sessionKey, "bob", "alice")

        assertArrayEquals("fs2-python-android".toByteArray(), receiver.decrypt(payload))
    }

    @Test
    fun importsReferencePythonStateWithoutResettingCounters() {
        val sessionKey = ByteArray(32) { it.toByte() }
        val pythonState =
            """{"my_id":"alice","peer_id":"bob","recv_ck":"b1qLvjPkseds2hkktQhHWGVlPq3GfuuKzFSqaQ148ZI=","recv_n":0,"send_ck":"wzRty13URS1ams5wiGfU1TJhTlUfUyJBk7FZf6eJd68=","send_n":1,"session_id":"pqF/41zZjqvqcYRkxMPlmQ==","skipped":{},"version":2}"""
                .toByteArray(Charsets.UTF_8)
        val alice = ForwardSecrecyChain.importState(sessionKey, "alice", "bob", pythonState)
        val bob = ForwardSecrecyChain(sessionKey, "bob", "alice")

        assertArrayEquals("after restart".toByteArray(), bob.decrypt(alice.encrypt("after restart".toByteArray())))
    }

    @Test
    fun encryptsInBothDirectionsAndAcceptsOutOfOrderMessages() {
        val sessionKey = ByteArray(32) { it.toByte() }
        val alice = ForwardSecrecyChain(sessionKey, "alice", "bob")
        val bob = ForwardSecrecyChain(sessionKey, "bob", "alice")

        val first = alice.encrypt("first".toByteArray())
        val second = alice.encrypt("second".toByteArray())
        val third = alice.encrypt("third".toByteArray())

        assertTrue(ForwardSecrecyChain.isPayload(first))
        assertEquals("FS2", String(first.copyOfRange(0, 3), Charsets.US_ASCII))
        assertEquals(2, ByteBuffer.wrap(third, 19, 4).order(ByteOrder.BIG_ENDIAN).int)
        assertArrayEquals("third".toByteArray(), bob.decrypt(third))
        assertArrayEquals("first".toByteArray(), bob.decrypt(first))
        assertArrayEquals("second".toByteArray(), bob.decrypt(second))

        val reply = bob.encrypt("reply".toByteArray())
        assertArrayEquals("reply".toByteArray(), alice.decrypt(reply))
    }

    @Test
    fun acceptsDelayedMessagesWithinWindowAndRejectsLargerGaps() {
        val sessionKey = ByteArray(32) { 7 }
        val alice = ForwardSecrecyChain(sessionKey, "alice", "bob")
        val bob = ForwardSecrecyChain(sessionKey, "bob", "alice")
        val message = alice.encrypt("once".toByteArray())

        assertArrayEquals("once".toByteArray(), bob.decrypt(message))
        assertThrows(IllegalArgumentException::class.java) { bob.decrypt(message) }

        val delayedSender = ForwardSecrecyChain(sessionKey, "alice", "bob")
        val delayedReceiver = ForwardSecrecyChain(sessionKey, "bob", "alice")
        val delayedFrames = List(101) { delayedSender.encrypt(byteArrayOf(it.toByte())) }
        assertArrayEquals(byteArrayOf(100), delayedReceiver.decrypt(delayedFrames.last()))
        assertArrayEquals(byteArrayOf(0), delayedReceiver.decrypt(delayedFrames.first()))

        val farAheadSender = ForwardSecrecyChain(sessionKey, "alice", "bob")
        val farAheadReceiver = ForwardSecrecyChain(sessionKey, "bob", "alice")
        var farAhead = ByteArray(0)
        repeat(1026) { farAhead = farAheadSender.encrypt(byteArrayOf(it.toByte())) }
        val error = assertThrows(IllegalArgumentException::class.java) {
            farAheadReceiver.decrypt(farAhead)
        }
        org.junit.Assert.assertTrue(error.message!!.contains("max=1024"))
    }

    @Test
    fun tamperedHeaderAndCiphertextDoNotAdvanceState() {
        val sessionKey = ByteArray(32) { 11 }
        val alice = ForwardSecrecyChain(sessionKey, "alice", "bob")
        val bob = ForwardSecrecyChain(sessionKey, "bob", "alice")
        val message = alice.encrypt("authentic".toByteArray())

        for (offset in listOf(5, 22, message.lastIndex)) {
            val corrupted = message.copyOf().also {
                it[offset] = (it[offset].toInt() xor 1).toByte()
            }
            val stateBefore = bob.exportState()
            assertThrows(Exception::class.java) { bob.decrypt(corrupted) }
            assertArrayEquals(stateBefore, bob.exportState())
        }
        assertArrayEquals("authentic".toByteArray(), bob.decrypt(message))
    }

    @Test
    fun stateRoundTripPreservesSendReceiveAndSkippedKeys() {
        val sessionKey = ByteArray(32) { it.toByte() }
        val alice = ForwardSecrecyChain(sessionKey, "alice", "bob")
        val bob = ForwardSecrecyChain(sessionKey, "bob", "alice")
        val first = alice.encrypt("first".toByteArray())
        val second = alice.encrypt("second".toByteArray())
        assertArrayEquals("second".toByteArray(), bob.decrypt(second))

        val restoredAlice = ForwardSecrecyChain.importState(
            sessionKey, "alice", "bob", alice.exportState()
        )
        val restoredBob = ForwardSecrecyChain.importState(
            sessionKey, "bob", "alice", bob.exportState()
        )
        assertArrayEquals("first".toByteArray(), restoredBob.decrypt(first))
        assertArrayEquals(
            "after restart".toByteArray(),
            restoredBob.decrypt(restoredAlice.encrypt("after restart".toByteArray()))
        )
    }

    @Test
    fun stateRejectsWrongIdentitySessionAndMalformedData() {
        val sessionKey = ByteArray(32) { 19 }
        val chain = ForwardSecrecyChain(sessionKey, "alice", "bob")
        val state = chain.exportState()

        assertThrows(IllegalArgumentException::class.java) {
            ForwardSecrecyChain.importState(sessionKey, "alice", "mallory", state)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ForwardSecrecyChain.importState(ByteArray(32) { 20 }, "alice", "bob", state)
        }
        assertThrows(Exception::class.java) {
            ForwardSecrecyChain.importState(sessionKey, "alice", "bob", byteArrayOf(1, 2))
        }
    }

    @Test
    fun persistedStateEncryptionIsBoundToBothParticipants() {
        val state = ForwardSecrecyChain(
            ByteArray(32) { it.toByte() },
            "alice",
            "bob"
        ).exportState()
        val masterKey = ByteArray(32) { 21 }
        val context = "fs2-state|alice|bob".toByteArray()
        val encrypted = CryptoEngine.encryptBytes(state, masterKey, context)

        assertArrayEquals(state, CryptoEngine.decryptBytes(encrypted, masterKey, context))
        assertThrows(Exception::class.java) {
            CryptoEngine.decryptBytes(
                encrypted,
                masterKey,
                "fs2-state|alice|mallory".toByteArray()
            )
        }
    }

    @Test
    fun legacyAndFs1FramesAreNotAcceptedByFs2() {
        val sessionKey = ByteArray(32) { 19 }
        val chain = ForwardSecrecyChain(sessionKey, "alice", "bob")
        val legacy = CryptoEngine.encryptMessage(sessionKey, "legacy".toByteArray())
        val fs1 = "FS1payload".toByteArray(Charsets.US_ASCII)

        assertFalse(ForwardSecrecyChain.isPayload(legacy))
        assertFalse(ForwardSecrecyChain.isPayload(fs1))
        assertThrows(IllegalArgumentException::class.java) { chain.decrypt(legacy) }
        assertThrows(IllegalArgumentException::class.java) { chain.decrypt(fs1) }
    }
}
