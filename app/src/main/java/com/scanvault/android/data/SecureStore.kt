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

    // The token is decrypted once and kept in memory, so the Keystore isn't hit on every request.
    @Volatile private var tokenCache: String? = null
    @Volatile private var tokenLoaded = false

    var token: String?
        get() {
            if (!tokenLoaded) {
                tokenCache = runCatching { prefs.getString(KEY_TOKEN) }.getOrNull()
                tokenLoaded = true
            }
            return tokenCache
        }
        set(value) {
            prefs.putString(KEY_TOKEN, value) // may throw if the Keystore fails; callers handle it
            tokenCache = value
            tokenLoaded = true
        }

    /** ISO-8601 expiry the server gave with the token; the app signs out locally once it passes. */
    var tokenExpiresAt: String?
        get() = prefs.getString(KEY_EXPIRES)
        set(value) = prefs.putString(KEY_EXPIRES, value)

    val tokenExpired: Boolean
        get() = tokenExpiresAt?.let { runCatching { java.time.OffsetDateTime.parse(it) }.getOrNull() }
            ?.isBefore(java.time.OffsetDateTime.now()) ?: false

    /** User opted in to unencrypted http, and only to private (LAN/VPN) addresses. */
    @Volatile var allowLanHttp: Boolean = prefs.getBoolean(KEY_ALLOW_HTTP, false)
        set(value) { field = value; prefs.putBoolean(KEY_ALLOW_HTTP, value) }

    /** SHA-256 fingerprints of self-signed server certificates the user approved. */
    @Volatile var certPins: Set<String> =
        prefs.getString(KEY_PINS)?.split(",")?.filter { it.isNotBlank() }?.toSet() ?: emptySet()
        private set

    fun addPin(fingerprint: String) {
        certPins = certPins + fingerprint
        prefs.putString(KEY_PINS, certPins.joinToString(","))
    }

    fun clearPins() {
        certPins = emptySet()
        prefs.remove(KEY_PINS)
    }

    /** Minutes in the background before the app lock is required again (0 = immediately). */
    var lockTimeoutMinutes: Int
        get() = prefs.getString(KEY_LOCK_TIMEOUT)?.toIntOrNull() ?: 1
        set(value) = prefs.putString(KEY_LOCK_TIMEOUT, value.toString())

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
        const val KEY_EXPIRES = "token_expires_at"
        const val KEY_ALLOW_HTTP = "allow_lan_http"
        const val KEY_PINS = "cert_pins"
        const val KEY_LOCK_TIMEOUT = "lock_timeout_min"
        const val LEGACY_TOKEN = "token_enc"
        const val LEGACY_ALIAS = "scanvault_token_key"
    }
}
