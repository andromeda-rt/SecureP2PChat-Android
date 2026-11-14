package com.example.securep2p.domain

import java.util.ArrayDeque

internal class PendingRelayInbox(private val maxPerPeer: Int = 50) {
    private val queues = mutableMapOf<String, ArrayDeque<ByteArray>>()

    @Synchronized
    fun enqueue(peerId: String, payload: ByteArray): Boolean {
        if (peerId.isBlank() || payload.isEmpty()) return false
        val queue = queues.getOrPut(peerId) { ArrayDeque() }
        if (queue.size >= maxPerPeer) return false
        queue.addLast(payload.copyOf())
        return true
    }

    @Synchronized
    fun takeAll(peerId: String): List<ByteArray> {
        val queue = queues.remove(peerId) ?: return emptyList()
        return buildList(queue.size) {
            while (queue.isNotEmpty()) add(queue.removeFirst())
        }
    }

    @Synchronized
    fun restoreFirst(peerId: String, payloads: List<ByteArray>) {
        if (payloads.isEmpty()) return
        val queue = queues.getOrPut(peerId) { ArrayDeque() }
        val retained = ArrayDeque<ByteArray>()
        payloads.forEach { retained.addLast(it.copyOf()) }
        queue.forEach { retained.addLast(it.copyOf()) }
        check(retained.size <= maxPerPeer) { "Pending relay inbox is full for peer" }
        queues[peerId] = retained
    }

    @Synchronized
    fun remove(peerId: String) {
        queues.remove(peerId)
    }
}
