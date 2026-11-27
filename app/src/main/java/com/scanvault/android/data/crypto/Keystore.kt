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
 * Non-exportable AES-256 keys in the Android Keystore: StrongBox when the phone has one,
 * otherwise the TEE. On Android 9+ the keys also only work while the phone is unlocked
 * (setUnlockedDeviceRequired), when the phone has a secure lock screen.
 *
 * These Keystore keys never leave secure hardware. The per-file data keys used for vault files
 * are generated in app memory and only ever stored wrapped (encrypted) by [FILES_ALIAS].
 */
object Keystore {
    const val PREFS_ALIAS = "scanvault_prefs_v2"
    const val FILES_ALIAS = "scanvault_files_v2"
    /** Key used by version 0.2.0 for preferences; read once to migrate, then deleted. */
    const val LEGACY_PREFS_ALIAS = "scanvault_prefs_v1"
    private const val PROVIDER = "AndroidKeyStore"
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val IV_LEN = 12

    private val keyStore: KeyStore by lazy { KeyStore.getInstance(PROVIDER).apply { load(null) } }

    @Synchronized
    fun existing(alias: String): SecretKey? = keyStore.getKey(alias, null) as? SecretKey

    @Synchronized
    fun delete(alias: String) { runCatching { keyStore.deleteEntry(alias) } }

    @Synchronized
    fun key(alias: String): SecretKey {
        existing(alias)?.let { return it }
        fun spec(strongBox: Boolean, unlockedOnly: Boolean) = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    if (strongBox) setIsStrongBoxBacked(true)
                    if (unlockedOnly) setUnlockedDeviceRequired(true)
                }
            }
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        // Strongest first; StrongBox or "unlocked only" can be unavailable (no secure lock screen).
        val attempts = listOf(true to true, false to true, true to false, false to false)
        var last: Exception? = null
        for ((strongBox, unlockedOnly) in attempts) {
            try {
                generator.init(spec(strongBox, unlockedOnly))
                return generator.generateKey()
            } catch (e: Exception) {
                last = e
            }
        }
        throw last ?: IllegalStateException("Couldn't create a Keystore key")
    }

    fun encrypt(alias: String, plain: ByteArray, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, key(alias))
        aad?.let { cipher.updateAAD(it) }
        return cipher.iv + cipher.doFinal(plain)
    }

    fun decrypt(alias: String, data: ByteArray, aad: ByteArray? = null): ByteArray {
        val key = existing(alias) ?: throw IllegalStateException("Key $alias is missing")
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, data, 0, IV_LEN))
        aad?.let { cipher.updateAAD(it) }
        return cipher.doFinal(data, IV_LEN, data.size - IV_LEN)
    }

    fun encryptString(alias: String, plain: String, aad: String? = null): String =
        Base64.encodeToString(encrypt(alias, plain.toByteArray(Charsets.UTF_8), aad?.toByteArray()), Base64.NO_WRAP)

    fun decryptString(alias: String, encoded: String, aad: String? = null): String =
        String(decrypt(alias, Base64.decode(encoded, Base64.NO_WRAP), aad?.toByteArray()), Charsets.UTF_8)

    /** Wraps a per-file software data key with the Keystore files key. */
    fun wrapDataKey(dataKey: SecretKey): ByteArray = encrypt(FILES_ALIAS, dataKey.encoded)

    fun unwrapDataKey(wrapped: ByteArray): SecretKey = SecretKeySpec(decrypt(FILES_ALIAS, wrapped), "AES")
}
