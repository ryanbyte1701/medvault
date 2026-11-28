package com.medvault.android.data

import android.content.Context
import android.util.Base64
import com.medvault.android.data.crypto.EncryptedPrefs
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
        get() {
            if (!serverLoaded) {
                serverCache = runCatching { prefs.getString(KEY_SERVER) }.getOrNull()
                serverLoaded = true
            }
            return serverCache
        }
        set(value) {
            prefs.putString(KEY_SERVER, value)
            serverCache = value
            serverLoaded = true
        }

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

    // Read on every request, so decrypted once and kept in memory (the Keystore is slow on StrongBox).
    @Volatile private var serverCache: String? = null
    @Volatile private var serverLoaded = false

    /**
     * The one host the user allowed unencrypted http to (their LAN/VPN server), or null.
     * Bound to that host so the opt-in doesn't carry over to other servers or networks' addresses.
     */
    @Volatile var lanHttpHost: String? = loadLanHttpHost()
        set(value) { field = value?.lowercase(); prefs.putString(KEY_HTTP_HOST, field) }

    fun allowsLanHttp(host: String): Boolean = lanHttpHost?.equals(host, ignoreCase = true) == true

    private fun loadLanHttpHost(): String? {
        prefs.getString(KEY_HTTP_HOST)?.let { return it }
        // 0.4.0 stored a global on/off switch; bind it to the saved server.
        if (prefs.getBoolean(KEY_ALLOW_HTTP, false)) {
            prefs.remove(KEY_ALLOW_HTTP)
            val host = serverUrl?.let { runCatching { java.net.URI(it).host }.getOrNull() }?.lowercase()
            prefs.putString(KEY_HTTP_HOST, host)
            return host
        }
        return null
    }

    /** Self-signed server certificates the user approved, as "host:port SHA256" (see CertPins). */
    @Volatile var certPins: Set<String> =
        prefs.getString(KEY_PINS)?.split(",")?.filter { it.contains(' ') }?.toSet() ?: emptySet()
        private set

    fun addPin(pinKey: String) {
        certPins = certPins + pinKey
        prefs.putString(KEY_PINS, certPins.joinToString(","))
    }

    fun clearPins() {
        certPins = emptySet()
        prefs.remove(KEY_PINS)
    }

    /** "url\ntoken" of a signed-out session the server hasn't confirmed revoking yet. */
    var pendingRevocation: String?
        get() = prefs.getString(KEY_REVOKE)
        set(value) = prefs.putString(KEY_REVOKE, value)

    /**
     * The server's device token for the last account signed in with a password. Kept after
     * sign-out on purpose: it is what lets this phone sign in while a stranger's wrong guesses
     * have the account locked. It only stands in for the lockout, never for the password.
     */
    fun deviceTokenFor(server: String, username: String): String? {
        val parts = prefs.getString(KEY_DEVICE)?.split("\n", limit = 3) ?: return null
        if (parts.size != 3) return null
        return parts[2].takeIf { parts[0] == server && parts[1].equals(username, ignoreCase = true) }
    }

    fun saveDeviceToken(server: String, username: String, token: String?) {
        if (token.isNullOrBlank() || '\n' in server || '\n' in username) return
        runCatching { prefs.putString(KEY_DEVICE, "$server\n$username\n$token") }
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
        const val KEY_HTTP_HOST = "lan_http_host"
        const val KEY_REVOKE = "pending_revocation"
        const val KEY_DEVICE = "login_device"
        const val KEY_PINS = "cert_pins"
        const val KEY_LOCK_TIMEOUT = "lock_timeout_min"
        const val LEGACY_TOKEN = "token_enc"
        const val LEGACY_ALIAS = "scanvault_token_key"
    }
}
