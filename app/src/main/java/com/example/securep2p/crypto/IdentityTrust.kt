package com.example.securep2p.crypto

import java.security.MessageDigest

object IdentityTrust {
    fun fingerprintTransitionAllowed(
        oldFingerprint: String,
        oldPublicKeyHex: String,
        newSigningFingerprint: String,
        peerPublicKeyHex: String
    ): Boolean {
        if (oldFingerprint.isEmpty() || oldFingerprint == newSigningFingerprint) return true
        if (oldPublicKeyHex.isEmpty() || peerPublicKeyHex.isEmpty()) return false

        return try {
            val oldPublicKey = oldPublicKeyHex.hexToByteArray()
            val peerPublicKey = peerPublicKeyHex.hexToByteArray()
            oldPublicKey.size == 32 &&
                peerPublicKey.size == 32 &&
                oldPublicKey.contentEquals(peerPublicKey) &&
                oldFingerprint == legacyFingerprint(oldPublicKey)
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private fun legacyFingerprint(publicKey: ByteArray): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(publicKey)
            .joinToString("") { "%02X".format(it) }
        return hash.chunked(4).take(12).joinToString(" ")
    }
}
