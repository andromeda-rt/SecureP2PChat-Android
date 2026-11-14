package com.example.securep2p

import com.example.securep2p.crypto.CryptoEngine
import com.example.securep2p.crypto.IdentityTrust
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityTrustTest {
    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun acceptsSameSigningKeyAndLegacyX25519FingerprintMigration() {
        val publicKey = ByteArray(32) { it.toByte() }
        val publicKeyHex = publicKey.toHexString()
        val legacyFingerprint = CryptoEngine.publicKeyFingerprint(publicKey)

        assertTrue(
            IdentityTrust.fingerprintTransitionAllowed(
                "same signing fingerprint",
                "",
                "same signing fingerprint",
                ""
            )
        )
        assertTrue(
            IdentityTrust.fingerprintTransitionAllowed(
                legacyFingerprint,
                publicKeyHex,
                "new signing fingerprint",
                publicKeyHex
            )
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun rejectsChangedOrUnrecognizedIdentityKey() {
        val oldPublicKey = ByteArray(32) { it.toByte() }
        val changedPublicKey = ByteArray(32) { (31 - it).toByte() }

        assertFalse(
            IdentityTrust.fingerprintTransitionAllowed(
                CryptoEngine.publicKeyFingerprint(oldPublicKey),
                oldPublicKey.toHexString(),
                "new signing fingerprint",
                changedPublicKey.toHexString()
            )
        )
        assertFalse(
            IdentityTrust.fingerprintTransitionAllowed(
                "unrecognized old fingerprint",
                oldPublicKey.toHexString(),
                "new signing fingerprint",
                oldPublicKey.toHexString()
            )
        )
    }
}
