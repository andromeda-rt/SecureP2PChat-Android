package com.example.securep2p

import com.example.securep2p.domain.PendingRelayInbox
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PendingRelayInboxTest {
    @Test
    fun preservesMessagesUntilSessionIsReadyAndRestoresFailedBatchFirst() {
        val inbox = PendingRelayInbox(maxPerPeer = 3)
        val first = byteArrayOf(1, 10)
        val second = byteArrayOf(2, 20)
        val third = byteArrayOf(3, 30)

        assertTrue(inbox.enqueue("peer", first))
        assertTrue(inbox.enqueue("peer", second))
        val batch = inbox.takeAll("peer")
        inbox.restoreFirst("peer", batch.drop(1))
        assertTrue(inbox.enqueue("peer", third))

        val remaining = inbox.takeAll("peer")
        assertArrayEquals(second, remaining[0])
        assertArrayEquals(third, remaining[1])
        assertTrue(inbox.takeAll("peer").isEmpty())
        assertFalse(inbox.enqueue("peer", byteArrayOf()))
    }

    @Test
    fun isolatesQueuesByPeerAndEnforcesCapacity() {
        val inbox = PendingRelayInbox(maxPerPeer = 1)

        assertTrue(inbox.enqueue("alice", byteArrayOf(1)))
        assertFalse(inbox.enqueue("alice", byteArrayOf(2)))
        assertTrue(inbox.enqueue("bob", byteArrayOf(3)))
        assertArrayEquals(byteArrayOf(3), inbox.takeAll("bob").single())
        assertArrayEquals(byteArrayOf(1), inbox.takeAll("alice").single())
    }
}
