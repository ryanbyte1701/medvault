package com.medvault.android.data.crypto

import android.content.Context
import android.content.SharedPreferences

/**
 * SharedPreferences whose values are all AES-GCM encrypted with a Keystore key, so nothing the
 * app remembers (server address, username, session token, appearance) is readable from its
 * data directory. Each value is bound to its key name (as GCM associated data), so ciphertexts
 * can't be swapped between entries.
 *
 * Values left by older versions (plaintext from 0.1.0, unbound ciphertext from 0.2.0) are all
 * migrated when the store is opened; after that, anything not in the current format is ignored.
 */
class EncryptedPrefs(context: Context, private val name: String) {
    private val prefs: SharedPreferences = context.getSharedPreferences(name, Context.MODE_PRIVATE)

    init {
        migrateAll()
    }

    private fun aad(key: String) = "$name/$key"

    fun getString(key: String): String? {
        val raw = prefs.getString(key, null) ?: return null
        if (!raw.startsWith(PREFIX)) return null
        return runCatching { Keystore.decryptString(Keystore.PREFS_ALIAS, raw.removePrefix(PREFIX), aad(key)) }.getOrNull()
    }

    fun putString(key: String, value: String?) {
        if (value == null) prefs.edit().remove(key).apply()
        else prefs.edit().putString(key, PREFIX + Keystore.encryptString(Keystore.PREFS_ALIAS, value, aad(key))).apply()
    }

    fun getBoolean(key: String, default: Boolean): Boolean = getString(key)?.toBooleanStrictOrNull() ?: default

    fun putBoolean(key: String, value: Boolean) = putString(key, value.toString())

    fun remove(key: String) = prefs.edit().remove(key).apply()

    /** Raw access for one-off migrations. */
    internal fun rawString(key: String): String? = prefs.getString(key, null)

    private fun migrateAll() {
        val entries = prefs.all
        if (entries.values.all { it is String && it.startsWith(PREFIX) }) return
        val editor = prefs.edit()
        for ((key, value) in entries) {
            val plain: String? = when {
                value is String && value.startsWith(PREFIX) -> continue
                value is String && value.startsWith(LEGACY_PREFIX) -> runCatching {
                    Keystore.decryptString(Keystore.LEGACY_PREFS_ALIAS, value.removePrefix(LEGACY_PREFIX))
                }.getOrNull()
                key == "token_enc" -> continue // 0.1.0 token, migrated by SecureStore with its own key
                value is String -> value
                value is Boolean || value is Int || value is Long || value is Float -> value.toString()
                else -> null
            }
            if (plain == null) editor.remove(key)
            else editor.putString(key, PREFIX + Keystore.encryptString(Keystore.PREFS_ALIAS, plain, aad(key)))
        }
        editor.commit()
    }

    private companion object {
        const val PREFIX = "e2:"
        const val LEGACY_PREFIX = "e1:"
    }
}
