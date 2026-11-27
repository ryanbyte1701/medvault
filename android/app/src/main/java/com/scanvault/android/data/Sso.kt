package com.scanvault.android.data

import android.content.Context
import com.scanvault.android.data.crypto.EncryptedPrefs
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** PKCE (RFC 7636) helpers for the SSO flow. */
object Pkce {
    private val random = SecureRandom()
    private val b64 = Base64.getUrlEncoder().withoutPadding()

    /** 32 random bytes as base64url: 43 URL-safe characters. */
    fun randomToken(): String = b64.encodeToString(ByteArray(32).also { random.nextBytes(it) })

    fun challenge(verifier: String): String =
        b64.encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))
}

/** An SSO sign-in in progress, kept (encrypted) across the trip to the browser. */
data class PendingSso(
    val server: String,
    val providerName: String,
    val state: String,
    val verifier: String,
    val startedAtMillis: Long,
) {
    val expired: Boolean get() = System.currentTimeMillis() - startedAtMillis > MAX_AGE_MS

    companion object {
        const val REDIRECT = "scanvault://sso"
        private const val MAX_AGE_MS = 10 * 60 * 1000L
    }
}

/** Survives the app being killed while the user signs in, so the result can still be completed. */
class PendingSsoStore(context: Context) {
    private val prefs = EncryptedPrefs(context, "sso_pending")

    fun save(p: PendingSso) {
        prefs.putString("server", p.server)
        prefs.putString("provider", p.providerName)
        prefs.putString("state", p.state)
        prefs.putString("verifier", p.verifier)
        prefs.putString("started", p.startedAtMillis.toString())
    }

    fun load(): PendingSso? {
        val server = prefs.getString("server") ?: return null
        return PendingSso(
            server = server,
            providerName = prefs.getString("provider") ?: "SSO",
            state = prefs.getString("state") ?: return null,
            verifier = prefs.getString("verifier") ?: return null,
            startedAtMillis = prefs.getString("started")?.toLongOrNull() ?: 0L,
        )
    }

    fun clear() {
        listOf("server", "provider", "state", "verifier", "started").forEach(prefs::remove)
    }
}

/**
 * What came back to scanvault://sso. Only the ticket and state are used: an error code from the
 * link is never shown, because any app or page can open the link with text of its choosing.
 */
sealed interface SsoResult {
    val state: String?

    data class Ticket(val ticket: String, override val state: String?) : SsoResult
    /** The user pressed Cancel on the server's confirmation page; return quietly. */
    data class Cancelled(override val state: String?) : SsoResult
    data class Failed(override val state: String?) : SsoResult

    companion object {
        fun parse(uri: android.net.Uri): SsoResult? {
            if (uri.scheme != "scanvault" || uri.host != "sso") return null
            val state = uri.getQueryParameter("state")
            uri.getQueryParameter("ticket")?.takeIf { it.isNotBlank() }?.let { return Ticket(it, state) }
            return if (uri.getQueryParameter("error") == "cancelled") Cancelled(state) else Failed(state)
        }
    }
}
