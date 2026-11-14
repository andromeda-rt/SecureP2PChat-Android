package com.example.securep2p.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.util.encoders.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * Logarithmic TreeKEM (RFC 9420 / MLS) ratchet tree.
 * Implements TreeKEM resolution, direct path updates O(log N), forward secrecy,
 * and post-compromise security (PCS).
 */
class TreeKEMGroup(
    val groupId: String,
    var epoch: Long,
    val myDeviceId: String,
    members: List<String>
) : AutoCloseable {

    val roster: List<String> = members.distinct().sorted()
    val memberCount: Int get() = roster.size
    val myLeafIndex: Int = roster.indexOf(myDeviceId)

    // Tree nodes: (level, index) -> 32-byte public key
    val publicNodes = mutableMapOf<NodeKey, ByteArray>()
    // Private keys on direct path: (level, index) -> 32-byte private key
    val privateNodes = mutableMapOf<NodeKey, ByteArray>()

    data class NodeKey(val level: Int, val index: Int) : Comparable<NodeKey> {
        override fun compareTo(other: NodeKey): Int {
            val lc = level.compareTo(other.level)
            return if (lc != 0) lc else index.compareTo(other.index)
        }
    }

    data class EncryptedSecret(
        val targetLevel: Int,
        val targetIndex: Int,
        val ephPub: ByteArray,
        val ciphertext: ByteArray
    )

    data class PathNode(
        val level: Int,
        val nodePub: ByteArray,
        val secrets: List<EncryptedSecret>
    )

    init {
        require(groupId.isNotBlank()) { "GroupId must not be blank" }
        require(roster.isNotEmpty()) { "Roster must not be empty" }
        require(myLeafIndex >= 0) { "Local device must be in group roster" }
    }

    fun treeHeight(): Int = calculateTreeHeight(memberCount)

    /**
     * Initializes a member's leaf keypair.
     */
    fun setLeafKeypair(leafIndex: Int, privateKey: ByteArray?, publicKey: ByteArray) {
        require(leafIndex in 0 until memberCount) { "Leaf index out of bounds" }
        require(publicKey.size == 32) { "Public key must be 32 bytes" }
        publicNodes[NodeKey(0, leafIndex)] = publicKey.copyOf()
        if (privateKey != null && leafIndex == myLeafIndex) {
            require(privateKey.size == 32) { "Private key must be 32 bytes" }
            privateNodes[NodeKey(0, leafIndex)] = privateKey.copyOf()
        }
    }

    /**
     * RFC 9420 resolution: returns non-blank nodes representing this subtree.
     */
    fun resolution(level: Int, index: Int): List<Pair<NodeKey, ByteArray>> {
        val key = NodeKey(level, index)
        val pub = publicNodes[key]
        if (pub != null) {
            return listOf(key to pub)
        }
        if (level == 0) {
            return emptyList()
        }
        val left = resolution(level - 1, index * 2)
        val right = resolution(level - 1, index * 2 + 1)
        return left + right
    }

    /**
     * Generates an O(log N) TreeKEM commit updating the direct path up to the root.
     * Returns: Pair of (Commit Frame Bytes, New 32-byte Epoch Secret).
     */
    @Synchronized
    fun generateCommit(): Pair<ByteArray, ByteArray> {
        val nextEpoch = epoch + 1
        val height = treeHeight()
        val pathNodes = mutableListOf<PathNode>()

        val secureRandom = SecureRandom()
        val leafSecret = ByteArray(32)
        secureRandom.nextBytes(leafSecret)

        var currentSecret = leafSecret
        // Update leaf keypair from leafSecret
        val myLeafKey = deriveX25519KeyPair(currentSecret, "MLS-TreeKEM-Leaf|$groupId|$nextEpoch|$myLeafIndex")
        publicNodes[NodeKey(0, myLeafIndex)] = myLeafKey.publicKey
        privateNodes[NodeKey(0, myLeafIndex)]?.fill(0)
        privateNodes[NodeKey(0, myLeafIndex)] = myLeafKey.privateKey

        for (l in 1..height) {
            val siblingIdx = (myLeafIndex shr (l - 1)) xor 1
            val targets = resolution(l - 1, siblingIdx)

            currentSecret = hkdf(currentSecret, "MLS-TreeKEM-Path|$groupId|$nextEpoch|$l".toByteArray(Charsets.UTF_8), 32)
            val nodeKeypair = deriveX25519KeyPair(currentSecret, "MLS-TreeKEM-Priv|$groupId|$nextEpoch|$l")
            val ancestorIdx = myLeafIndex shr l
            publicNodes[NodeKey(l, ancestorIdx)] = nodeKeypair.publicKey
            privateNodes[NodeKey(l, ancestorIdx)]?.fill(0)
            privateNodes[NodeKey(l, ancestorIdx)] = nodeKeypair.privateKey

            val encryptedList = mutableListOf<EncryptedSecret>()
            for ((targetKey, targetPub) in targets) {
                val eph = CryptoEngine.generateX25519KeyPair()
                val shared = CryptoEngine.rawKeyAgreement(eph.privateKey, targetPub)
                val encKey = hkdf(shared, "MLS-TreeKEM-EncKey|$groupId|$nextEpoch|$l|${targetKey.level},${targetKey.index}".toByteArray(Charsets.UTF_8), 32)
                val aad = "MLS-TreeKEM-AAD|$groupId|$nextEpoch|$l|${targetKey.level},${targetKey.index}".toByteArray(Charsets.UTF_8)
                val ct = CryptoEngine.encryptBytes(currentSecret, encKey, aad)
                eph.privateKey.fill(0)
                shared.fill(0)
                encKey.fill(0)
                encryptedList.add(EncryptedSecret(targetKey.level, targetKey.index, eph.publicKey, ct))
            }
            pathNodes.add(PathNode(l, nodeKeypair.publicKey, encryptedList))
        }

        val epochSecret = hkdf(currentSecret, "MLS-TreeKEM-EpochSecret|$groupId|$nextEpoch".toByteArray(Charsets.UTF_8), 32)
        epoch = nextEpoch
        val frame = serializeCommit(nextEpoch, myLeafIndex, roster.size, pathNodes)
        return frame to epochSecret
    }

    /**
     * Processes an incoming O(log N) TreeKEM commit frame.
     * Returns: The new 32-byte Epoch Secret derived identically by all members.
     */
    @Synchronized
    fun processCommit(frame: ByteArray): ByteArray {
        val (commitEpoch, committerLeaf, rosterCount, pathNodes) = parseCommit(frame)
        require(rosterCount == roster.size) { "Commit roster count mismatch ($rosterCount vs ${roster.size})" }
        require(committerLeaf in 0 until memberCount) { "Committer leaf out of bounds" }
        require(commitEpoch == epoch + 1) { "Commit epoch mismatch (expected ${epoch + 1}, got $commitEpoch)" }

        if (committerLeaf == myLeafIndex) {
            return ByteArray(0)
        }

        val diff = myLeafIndex xor committerLeaf
        val intersectLevel = 32 - Integer.numberOfLeadingZeros(diff)
        val height = treeHeight()
        require(intersectLevel in 1..height) { "Invalid tree intersection level $intersectLevel" }

        val pathNode = pathNodes.firstOrNull { it.level == intersectLevel }
            ?: error("Commit path missing intersection level $intersectLevel")

        // Find which target in pathNode.secrets we have the private key for
        var decryptedSecret: ByteArray? = null
        for (secretItem in pathNode.secrets) {
            val priv = privateNodes[NodeKey(secretItem.targetLevel, secretItem.targetIndex)]
            if (priv != null) {
                val shared = CryptoEngine.rawKeyAgreement(priv, secretItem.ephPub)
                val encKey = hkdf(shared, "MLS-TreeKEM-EncKey|$groupId|$commitEpoch|$intersectLevel|${secretItem.targetLevel},${secretItem.targetIndex}".toByteArray(Charsets.UTF_8), 32)
                val aad = "MLS-TreeKEM-AAD|$groupId|$commitEpoch|$intersectLevel|${secretItem.targetLevel},${secretItem.targetIndex}".toByteArray(Charsets.UTF_8)
                decryptedSecret = CryptoEngine.decryptBytes(secretItem.ciphertext, encKey, aad)
                shared.fill(0)
                encKey.fill(0)
                break
            }
        }

        var currentSecret = decryptedSecret
            ?: error("Could not decrypt TreeKEM path at level $intersectLevel (no matching private key)")

        // Derive and store ancestor keypair at intersection level
        val ancestorIdx = committerLeaf shr intersectLevel
        val ancestorKeypair = deriveX25519KeyPair(currentSecret, "MLS-TreeKEM-Priv|$groupId|$commitEpoch|$intersectLevel")
        publicNodes[NodeKey(intersectLevel, ancestorIdx)] = ancestorKeypair.publicKey
        privateNodes[NodeKey(intersectLevel, ancestorIdx)]?.fill(0)
        privateNodes[NodeKey(intersectLevel, ancestorIdx)] = ancestorKeypair.privateKey

        // Ascend up to root
        for (l in (intersectLevel + 1)..height) {
            currentSecret = hkdf(currentSecret, "MLS-TreeKEM-Path|$groupId|$commitEpoch|$l".toByteArray(Charsets.UTF_8), 32)
            val higherIdx = committerLeaf shr l
            val higherKeypair = deriveX25519KeyPair(currentSecret, "MLS-TreeKEM-Priv|$groupId|$commitEpoch|$l")
            publicNodes[NodeKey(l, higherIdx)] = higherKeypair.publicKey
            privateNodes[NodeKey(l, higherIdx)]?.fill(0)
            privateNodes[NodeKey(l, higherIdx)] = higherKeypair.privateKey
        }

        // Update all public keys published in commit
        for (node in pathNodes) {
            val idx = committerLeaf shr node.level
            publicNodes[NodeKey(node.level, idx)] = node.nodePub.copyOf()
        }

        val epochSecret = hkdf(currentSecret, "MLS-TreeKEM-EpochSecret|$groupId|$commitEpoch".toByteArray(Charsets.UTF_8), 32)
        epoch = commitEpoch
        return epochSecret
    }

    fun exportState(): ByteArray {
        val pubJson = JSONObject()
        for ((k, v) in publicNodes) {
            pubJson.put("${k.level},${k.index}", Base64.toBase64String(v))
        }
        val privJson = JSONObject()
        for ((k, v) in privateNodes) {
            privJson.put("${k.level},${k.index}", Base64.toBase64String(v))
        }
        val rosterArr = JSONArray()
        roster.forEach { rosterArr.put(it) }

        return JSONObject().apply {
            put("version", 1)
            put("group_id", groupId)
            put("epoch", epoch)
            put("my_id", myDeviceId)
            put("roster", rosterArr)
            put("public_nodes", pubJson)
            put("private_nodes", privJson)
        }.toString().toByteArray(Charsets.UTF_8)
    }

    override fun close() {
        destroy()
    }

    fun destroy() {
        privateNodes.values.forEach { it.fill(0) }
        privateNodes.clear()
        publicNodes.clear()
    }

    companion object {
        val MAGIC = "TKEM".toByteArray(Charsets.US_ASCII)
        const val VERSION: Byte = 1

        fun calculateTreeHeight(n: Int): Int {
            if (n <= 1) return 1
            var h = 0
            var temp = n - 1
            while (temp > 0) {
                h++
                temp = temp shr 1
            }
            return maxOf(1, h)
        }

        fun isCommitFrame(payload: ByteArray): Boolean {
            return payload.size >= 19 &&
                    payload[0] == MAGIC[0] &&
                    payload[1] == MAGIC[1] &&
                    payload[2] == MAGIC[2] &&
                    payload[3] == MAGIC[3] &&
                    payload[4] == VERSION
        }

        private fun deriveX25519KeyPair(secret: ByteArray, info: String): X25519KeyPair {
            val privBytes = hkdf(secret, info.toByteArray(Charsets.UTF_8), 32)
            val priv = X25519PrivateKeyParameters(privBytes, 0)
            val pub = priv.generatePublicKey()
            return X25519KeyPair(priv.encoded, pub.encoded)
        }

        private fun hkdf(ikm: ByteArray, info: ByteArray, len: Int): ByteArray {
            val gen = HKDFBytesGenerator(SHA256Digest())
            gen.init(HKDFParameters(ikm, null, info))
            val res = ByteArray(len)
            gen.generateBytes(res, 0, len)
            return res
        }

        fun serializeCommit(
            epoch: Long,
            committerLeaf: Int,
            rosterCount: Int,
            pathNodes: List<PathNode>
        ): ByteArray {
            var totalSize = 4 + 1 + 8 + 4 + 2 + 4
            for (p in pathNodes) {
                totalSize += 1 + 32 + 2 // level (1B), nodePub (32B), secretsCount (2B)
                for (s in p.secrets) {
                    totalSize += 1 + 4 + 32 + 2 + s.ciphertext.size
                }
            }
            val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN)
            buf.put(MAGIC)
            buf.put(VERSION)
            buf.putLong(epoch)
            buf.putInt(committerLeaf)
            buf.putShort(rosterCount.toShort())
            buf.putInt(pathNodes.size)
            for (p in pathNodes) {
                buf.put(p.level.toByte())
                buf.put(p.nodePub)
                buf.putShort(p.secrets.size.toShort())
                for (s in p.secrets) {
                    buf.put(s.targetLevel.toByte())
                    buf.putInt(s.targetIndex)
                    buf.put(s.ephPub)
                    buf.putShort(s.ciphertext.size.toShort())
                    buf.put(s.ciphertext)
                }
            }
            return buf.array()
        }

        data class ParsedCommit(
            val epoch: Long,
            val committerLeaf: Int,
            val rosterCount: Int,
            val pathNodes: List<PathNode>
        )

        fun parseCommit(frame: ByteArray): ParsedCommit {
            require(isCommitFrame(frame)) { "Invalid TreeKEM commit frame" }
            val buf = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN)
            buf.position(4 + 1) // Skip MAGIC + VERSION
            val epoch = buf.long
            val committerLeaf = buf.int
            val rosterCount = buf.short.toInt() and 0xFFFF
            val pathCount = buf.int
            val nodes = mutableListOf<PathNode>()
            for (i in 0 until pathCount) {
                val level = buf.get().toInt() and 0xFF
                val nodePub = ByteArray(32)
                buf.get(nodePub)
                val secretCount = buf.short.toInt() and 0xFFFF
                val secrets = mutableListOf<EncryptedSecret>()
                for (j in 0 until secretCount) {
                    val targetLevel = buf.get().toInt() and 0xFF
                    val targetIdx = buf.int
                    val ephPub = ByteArray(32)
                    buf.get(ephPub)
                    val ctLen = buf.short.toInt() and 0xFFFF
                    val ct = ByteArray(ctLen)
                    buf.get(ct)
                    secrets.add(EncryptedSecret(targetLevel, targetIdx, ephPub, ct))
                }
                nodes.add(PathNode(level, nodePub, secrets))
            }
            return ParsedCommit(epoch, committerLeaf, rosterCount, nodes)
        }

        fun importState(raw: ByteArray): TreeKEMGroup {
            val json = JSONObject(String(raw, Charsets.UTF_8))
            require(json.getInt("version") == 1) { "Unsupported TreeKEM state version" }
            val groupId = json.getString("group_id")
            val epoch = json.getLong("epoch")
            val myId = json.getString("my_id")
            val rosterJson = json.getJSONArray("roster")
            val roster = mutableListOf<String>()
            for (i in 0 until rosterJson.length()) {
                roster.add(rosterJson.getString(i))
            }
            val group = TreeKEMGroup(groupId, epoch, myId, roster)
            val pubJson = json.getJSONObject("public_nodes")
            val pubKeys = pubJson.keys()
            while (pubKeys.hasNext()) {
                val k = pubKeys.next()
                val parts = k.split(",")
                val level = parts[0].toInt()
                val idx = parts[1].toInt()
                group.publicNodes[NodeKey(level, idx)] = Base64.decode(pubJson.getString(k))
            }
            val privJson = json.getJSONObject("private_nodes")
            val privKeys = privJson.keys()
            while (privKeys.hasNext()) {
                val k = privKeys.next()
                val parts = k.split(",")
                val level = parts[0].toInt()
                val idx = parts[1].toInt()
                group.privateNodes[NodeKey(level, idx)] = Base64.decode(privJson.getString(k))
            }
            return group
        }
    }
}
