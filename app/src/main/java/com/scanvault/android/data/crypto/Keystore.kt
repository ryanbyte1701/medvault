package com.scanvault.android.data.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Non-exportable AES-256 keys in the Android Keystore (StrongBox secure element when the phone has
 * one, otherwise the TEE). Key material never enters app memory; only ciphertext does.
 */
object Keystore {
    const val PREFS_ALIAS = "scanvault_prefs_v1"
    const val FILES_ALIAS = "scanvault_files_v1"
    private const val PROVIDER = "AndroidKeyStore"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val IV_LEN = 12

    private val keyStore: KeyStore by lazy { KeyStore.getInstance(PROVIDER).apply { load(null) } }

    @Synchronized
    fun key(alias: String): SecretKey {
        (keyStore.getKey(alias, null) as? SecretKey)?.let { return it }
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .apply { if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true) }
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        return try {
            generator.init(spec(strongBox = true)); generator.generateKey()
        } catch (e: Exception) {
            // No StrongBox (or it refused this key): use the TEE-backed Keystore instead.
            generator.init(spec(strongBox = false)); generator.generateKey()
        }
    }

    fun encrypt(alias: String, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key(alias))
        return cipher.iv + cipher.doFinal(plain)
    }

    fun decrypt(alias: String, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key(alias), GCMParameterSpec(128, data, 0, IV_LEN))
        return cipher.doFinal(data, IV_LEN, data.size - IV_LEN)
    }

    fun encryptString(alias: String, plain: String): String =
        Base64.encodeToString(encrypt(alias, plain.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)

    fun decryptString(alias: String, encoded: String): String =
        String(decrypt(alias, Base64.decode(encoded, Base64.NO_WRAP)), Charsets.UTF_8)

    /** Wraps a per-file software data key with the Keystore files key. */
    fun wrapDataKey(dataKey: SecretKey): ByteArray = encrypt(FILES_ALIAS, dataKey.encoded)

    fun unwrapDataKey(wrapped: ByteArray): SecretKey = SecretKeySpec(decrypt(FILES_ALIAS, wrapped), "AES")
}
