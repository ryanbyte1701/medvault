package com.scanvault.android.data.crypto

import android.content.Context

/**
 * SharedPreferences whose values are all AES-GCM encrypted with a Keystore key, so nothing the
 * app remembers (server address, username, session token, appearance) is readable from its
 * data directory. Plaintext values left by older versions are encrypted on first read.
 */
class EncryptedPrefs(context: Context, name: String) {
    private val prefs = context.getSharedPreferences(name, Context.MODE_PRIVATE)

    fun getString(key: String): String? {
        val raw = prefs.getString(key, null) ?: return null
        if (!raw.startsWith(PREFIX)) {
            // Migrate a value written before encryption was added.
            putString(key, raw)
            return raw
        }
        return runCatching { Keystore.decryptString(Keystore.PREFS_ALIAS, raw.removePrefix(PREFIX)) }.getOrNull()
    }

    fun putString(key: String, value: String?) {
        if (value == null) prefs.edit().remove(key).apply()
        else prefs.edit().putString(key, PREFIX + Keystore.encryptString(Keystore.PREFS_ALIAS, value)).apply()
    }

    fun getBoolean(key: String, default: Boolean): Boolean {
        // Booleans from older versions were stored natively; read and migrate them.
        val all = prefs.all[key]
        if (all is Boolean) { putBoolean(key, all); return all }
        return getString(key)?.toBooleanStrictOrNull() ?: default
    }

    fun putBoolean(key: String, value: Boolean) {
        prefs.edit().remove(key).apply()
        putString(key, value.toString())
    }

    fun remove(key: String) = prefs.edit().remove(key).apply()

    /** Raw access for one-off migrations. */
    internal fun rawString(key: String): String? = prefs.getString(key, null)

    private companion object {
        const val PREFIX = "e1:"
    }
}
