package com.example.securep2p

import com.example.securep2p.crypto.CryptoEngine
import com.example.securep2p.crypto.TreeKEMGroup
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TreeKEMGroupTest {

    @Test
    fun twoMemberGroupTreeKEMCommitMatchesEpochSecret() {
        val roster = listOf("alice", "bob")
        val alice = TreeKEMGroup("group-2", 0, "alice", roster)
        val bob = TreeKEMGroup("group-2", 0, "bob", roster)

        val bobKey = CryptoEngine.generateX25519KeyPair()
        alice.setLeafKeypair(1, null, bobKey.publicKey)
        bob.setLeafKeypair(1, bobKey.privateKey, bobKey.publicKey)

        val (commitFrame, aliceEpochSecret) = alice.generateCommit()
        assertTrue(TreeKEMGroup.isCommitFrame(commitFrame))
        assertEquals(1L, alice.epoch)

        val bobEpochSecret = bob.processCommit(commitFrame)
        assertEquals(1L, bob.epoch)
        assertArrayEquals(aliceEpochSecret, bobEpochSecret)

        alice.destroy()
        bob.destroy()
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun decryptsReferencePythonTreeKEMCommit() {
        val roster = listOf("alice", "bob")
        val bob = TreeKEMGroup("group-interop", 0, "bob", roster)

        val privB = "e7ba46929cab043984f8341fa0f4f0b8cd7db1d2117c9fa3b91f8c35f8017b6a".hexToByteArray()
        val pubB = "b501a9c9d9ceee162f82bd52bc2df1ae8782fb02d2fa37d0dd60af11ba1f8871".hexToByteArray()
        bob.setLeafKeypair(1, privB, pubB)

        val frameB64 = "VEtFTQEAAAAAAAAAAQAAAAAAAgAAAAEBMcgTvfcI4t0AHszIgJjtBuGr5UPQ6q9hAJ9/fb4vqXoAAQAAAAABTTrpMkzTVmPOLhf4RkDV2E9rO+OF5A1Ue6LEw3WZrAoATVNQQzICdy3Qt3r3bzz4CnkUi+N9+/bSni5krBEgOBXMj5OpvuBCh68JyLM/AomK9ezWPMNoKTNdnPBuNDFtQn/vGNpd8pK9Y7vQbkoZ"
        val frame = org.bouncycastle.util.encoders.Base64.decode(frameB64)

        val bobEpochSec = bob.processCommit(frame)
        assertEquals(1L, bob.epoch)
        assertEquals(
            "1c6811341e5b7585da5f9d4cb3f3b52b1841331ba334f2dcd6af56181cccda9f",
            bobEpochSec.toHexString()
        )
        bob.destroy()
    }

    @Test
    fun multiMemberTreeKEMCommitDerivesIdenticalEpochSecretAcrossAllMembers() {
        val roster = listOf("alice", "bob", "charlie", "dave", "eve") // N=5, H=3
        val members = mutableListOf<TreeKEMGroup>()
        val initialKeys = roster.map { CryptoEngine.generateX25519KeyPair() }

        roster.forEachIndexed { idx, id ->
            val g = TreeKEMGroup("group-5", 0, id, roster)
            initialKeys.forEachIndexed { keyIdx, kp ->
                g.setLeafKeypair(keyIdx, if (keyIdx == idx) kp.privateKey else null, kp.publicKey)
            }
            members.add(g)
        }

        // Alice (index 0) commits for epoch 1
        val (commit1, aliceSecret1) = members[0].generateCommit()
        for (i in 1 until members.size) {
            val sec = members[i].processCommit(commit1)
            assertArrayEquals(aliceSecret1, sec)
            assertEquals(1L, members[i].epoch)
        }

        // Dave (index 3) commits for epoch 2 (PCS update)
        val (commit2, daveSecret2) = members[3].generateCommit()
        assertEquals(2L, members[3].epoch)
        for (i in 0 until members.size) {
            if (i == 3) continue
            val sec = members[i].processCommit(commit2)
            assertArrayEquals(daveSecret2, sec)
            assertEquals(2L, members[i].epoch)
        }

        members.forEach { it.destroy() }
    }

    @Test
    fun treeKEMStateExportAndImportPreservesRatchet() {
        val roster = listOf("alice", "bob", "charlie")
        val alice = TreeKEMGroup("group-3", 0, "alice", roster)
        val bob = TreeKEMGroup("group-3", 0, "bob", roster)
        val charlie = TreeKEMGroup("group-3", 0, "charlie", roster)

        val keys = roster.map { CryptoEngine.generateX25519KeyPair() }
        listOf(alice, bob, charlie).forEachIndexed { mIdx, g ->
            keys.forEachIndexed { kIdx, kp ->
                g.setLeafKeypair(kIdx, if (kIdx == mIdx) kp.privateKey else null, kp.publicKey)
            }
        }

        val (commit, aliceSec) = alice.generateCommit()
        bob.processCommit(commit)
        charlie.processCommit(commit)

        // Export and re-import Bob
        val bobState = bob.exportState()
        val restoredBob = TreeKEMGroup.importState(bobState)
        assertEquals(bob.groupId, restoredBob.groupId)
        assertEquals(bob.epoch, restoredBob.epoch)
        assertEquals(bob.myLeafIndex, restoredBob.myLeafIndex)

        // Charlie commits for epoch 2, restored Bob must be able to process it
        val (commit2, charlieSec2) = charlie.generateCommit()
        val bobSec2 = restoredBob.processCommit(commit2)
        assertArrayEquals(charlieSec2, bobSec2)

        alice.destroy()
        bob.destroy()
        charlie.destroy()
        restoredBob.destroy()
    }
}
