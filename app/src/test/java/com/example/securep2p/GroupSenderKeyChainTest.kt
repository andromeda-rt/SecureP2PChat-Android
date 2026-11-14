package com.example.securep2p

import com.example.securep2p.crypto.GroupSenderKeyChain
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import org.bouncycastle.util.encoders.Base64

class GroupSenderKeyChainTest {
    @Test
    fun decryptsPythonSenderKeyFrame() {
        val secret = ByteArray(32) { it.toByte() }
        val frame = Base64.decode(
            "R1NLMQAAAAAAAAAJAAAAAFNQQzICRJT6eSz8eVM9qoBKIt0y8wOBaoy1CBGkoxWh2zp8pMFz9OtixCH2q2aDwpdzAsJ1lq+OwYSmrcT3T6Ex9JS8eqyKD+oJ7QAuuqB3mb75eg=="
        )
        val chain = GroupSenderKeyChain(secret, "group-xplat", 9, "python-sender")
        assertArrayEquals(
            """{"kind":"text","text":"cross-platform"}""".toByteArray(),
            chain.decrypt(frame)
        )
        chain.destroy()
    }

    @Test
    fun decryptsGroupFramesOutOfOrderAndRejectsReplay() {
        val secret = ByteArray(32) { it.toByte() }
        val sender = GroupSenderKeyChain(secret, "group-1", 4, "alice")
        val receiver = GroupSenderKeyChain(secret, "group-1", 4, "alice")
        val frames = List(3) { sender.encrypt("message-$it".toByteArray()) }

        assertTrue(GroupSenderKeyChain.isFrame(frames[2]))
        assertArrayEquals("message-2".toByteArray(), receiver.decrypt(frames[2]))
        assertArrayEquals("message-0".toByteArray(), receiver.decrypt(frames[0]))
        assertArrayEquals("message-1".toByteArray(), receiver.decrypt(frames[1]))
        assertThrows(IllegalArgumentException::class.java) { receiver.decrypt(frames[1]) }
    }

    @Test
    fun stateRoundTripPreservesSkippedKeysAndRejectsTampering() {
        val secret = ByteArray(32) { (it + 3).toByte() }
        val sender = GroupSenderKeyChain(secret, "group-2", 7, "bob")
        val receiver = GroupSenderKeyChain(secret, "group-2", 7, "bob")
        val first = sender.encrypt("first".toByteArray())
        val second = sender.encrypt("second".toByteArray())
        assertArrayEquals("second".toByteArray(), receiver.decrypt(second))

        val restoredSender = GroupSenderKeyChain.importState(secret, sender.exportState())
        val restoredReceiver = GroupSenderKeyChain.importState(secret, receiver.exportState())
        assertArrayEquals("first".toByteArray(), restoredReceiver.decrypt(first))
        assertArrayEquals(
            "after restart".toByteArray(),
            restoredReceiver.decrypt(restoredSender.encrypt("after restart".toByteArray()))
        )

        val tampered = sender.encrypt("authentic".toByteArray()).also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        val freshReceiver = GroupSenderKeyChain(secret, "group-2", 7, "bob")
        assertThrows(Exception::class.java) { freshReceiver.decrypt(tampered) }
        assertFalse(GroupSenderKeyChain.isFrame(byteArrayOf(1, 2, 3)))
        sender.destroy()
        receiver.destroy()
        restoredSender.destroy()
        restoredReceiver.destroy()
        freshReceiver.destroy()
    }
}
