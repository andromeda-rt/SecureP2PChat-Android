package com.example.securep2p.data

import android.content.Context
import android.os.Build
import android.provider.Settings
import com.example.securep2p.crypto.CryptoEngine
import com.example.securep2p.crypto.Ed25519KeyPair
import com.example.securep2p.crypto.X25519KeyPair
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

class IdentityManager(private val context: Context) {
    private val identityFile: File by lazy {
        File(context.filesDir, "identity.bin")
    }

    var x25519KeyPair: X25519KeyPair? = null
        private set

    var ed25519KeyPair: Ed25519KeyPair? = null
        private set

    var deviceId: String? = null
        private set

    var displayName: String? = null
        private set

    var masterKey: ByteArray? = null
        private set

    fun exists(): Boolean {
        return identityFile.exists() && identityFile.length() >= 45
    }

    fun isUnlocked(): Boolean {
        return x25519KeyPair != null && ed25519KeyPair != null && deviceId != null
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun create(name: String, password: String): Boolean {
        return try {
            val trimmedName = name.trim().ifEmpty { "AndroidUser" }
            val keyPair = CryptoEngine.generateX25519KeyPair()
            val signingPair = CryptoEngine.deriveEd25519KeyPair(keyPair.privateKey)

            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)

            val androidId = try {
                Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: ""
            } catch (e: Exception) {
                ""
            }
            val hwFp = "${Build.MANUFACTURER}:${Build.MODEL}:$androidId:${UUID.randomUUID()}"
            val md = MessageDigest.getInstance("SHA-256")
            val idHash = md.digest(hwFp.toByteArray(Charsets.UTF_8)).toHexString()
            val devId = idHash.take(32)

            val derivedMasterKey = CryptoEngine.deriveKeyFromPassword(password, salt)

            val payload = JSONObject().apply {
                put("device_id", devId)
                put("display_name", trimmedName)
                put("public_key", keyPair.publicKey.toHexString())
                put("private_key", keyPair.privateKey.toHexString())
                put("version", 3)
            }

            val encrypted = CryptoEngine.encryptBytes(
                payload.toString().toByteArray(Charsets.UTF_8),
                derivedMasterKey,
                "storage".toByteArray(Charsets.UTF_8)
            )

            identityFile.parentFile?.mkdirs()
            val totalBytes = ByteArray(salt.size + encrypted.size)
            System.arraycopy(salt, 0, totalBytes, 0, salt.size)
            System.arraycopy(encrypted, 0, totalBytes, salt.size, encrypted.size)
            identityFile.writeBytes(totalBytes)

            this.x25519KeyPair = keyPair
            this.ed25519KeyPair = signingPair
            this.deviceId = devId
            this.displayName = trimmedName
            this.masterKey = derivedMasterKey
            true
        } catch (t: Throwable) {
            t.printStackTrace()
            lock()
            false
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun unlock(password: String): Boolean {
        if (!exists()) return false
        return try {
            val fileBytes = identityFile.readBytes()
            if (fileBytes.size < 45) return false

            val salt = fileBytes.copyOfRange(0, 16)
            val derivedMasterKey = CryptoEngine.deriveKeyFromPassword(password, salt)
            val encrypted = fileBytes.copyOfRange(16, fileBytes.size)

            val decrypted = CryptoEngine.decryptBytes(
                encrypted,
                derivedMasterKey,
                "storage".toByteArray(Charsets.UTF_8)
            )

            val json = JSONObject(String(decrypted, Charsets.UTF_8))
            val devId = json.getString("device_id")
            val name = json.getString("display_name")
            val pubHex = json.getString("public_key")
            val privHex = json.getString("private_key")

            val privBytes = privHex.hexToByteArray()
            val pubBytes = pubHex.hexToByteArray()
            val keyPair = X25519KeyPair(privBytes, pubBytes)
            val signingPair = CryptoEngine.deriveEd25519KeyPair(privBytes)

            this.x25519KeyPair = keyPair
            this.ed25519KeyPair = signingPair
            this.deviceId = devId
            this.displayName = name
            this.masterKey = derivedMasterKey
            true
        } catch (t: Throwable) {
            t.printStackTrace()
            lock()
            false
        }
    }

    fun getFingerprint(): String {
        val pub = x25519KeyPair?.publicKey ?: return ""
        return CryptoEngine.publicKeyFingerprint(pub)
    }

    fun lock() {
        x25519KeyPair = null
        ed25519KeyPair = null
        deviceId = null
        displayName = null
        masterKey = null
    }

    fun deleteIdentity() {
        lock()
        if (identityFile.exists()) {
            identityFile.delete()
        }
    }
}
