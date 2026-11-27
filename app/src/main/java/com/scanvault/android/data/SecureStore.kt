package com.scanvault.android.data

import android.content.Context
import android.util.Base64
import com.scanvault.android.data.crypto.EncryptedPrefs
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Sign-in details, all encrypted at rest with an Android Keystore key (see [EncryptedPrefs]).
 * The vault passphrase and recovery key are never stored on the device.
 */
class SecureStore(context: Context) {
    private val prefs = EncryptedPrefs(context, "scanvault")

    init {
        migrateLegacyToken()
    }

    var serverUrl: String?
        get() = prefs.getString(KEY_SERVER)
        set(value) = prefs.putString(KEY_SERVER, value)

    var username: String?
        get() = prefs.getString(KEY_USER)
        set(value) = prefs.putString(KEY_USER, value)

    var token: String?
        get() = prefs.getString(KEY_TOKEN)
        set(value) = prefs.putString(KEY_TOKEN, value)

    /**
     * Version 0.1.0 kept the token under "token_enc", encrypted with its own Keystore key.
     * Move it under the shared prefs key and drop the old key.
     */
    private fun migrateLegacyToken() {
        val legacy = prefs.rawString(LEGACY_TOKEN) ?: return
        runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = ks.getKey(LEGACY_ALIAS, null) as? SecretKey ?: return@runCatching null
            val bytes = Base64.decode(legacy, Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes, 0, 12))
            String(cipher.doFinal(bytes, 12, bytes.size - 12), Charsets.UTF_8).also {
                ks.deleteEntry(LEGACY_ALIAS)
            }
        }.getOrNull()?.let { token = it }
        prefs.remove(LEGACY_TOKEN)
    }

    private companion object {
        const val KEY_SERVER = "server_url"
        const val KEY_USER = "username"
        const val KEY_TOKEN = "token"
        const val LEGACY_TOKEN = "token_enc"
        const val LEGACY_ALIAS = "scanvault_token_key"
    }
}
