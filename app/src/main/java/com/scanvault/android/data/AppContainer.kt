package com.scanvault.android.data

import android.content.Context
import android.os.Handler
import android.os.Looper
import coil.ImageLoader
import coil.disk.DiskCache
import com.scanvault.android.data.crypto.FileVault
import com.scanvault.android.data.crypto.SecureFileProvider
import com.scanvault.android.data.net.HttpClients
import com.scanvault.android.data.net.InsecureConnectionException
import com.scanvault.android.ui.components.userMessage
import java.security.MessageDigest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import java.io.File

/** Session-level state shared by every screen. */
sealed interface SessionState {
    data object SignedOut : SessionState
    data object Ready : SessionState
    data object Locked : SessionState
}

/** Saving the session on the phone failed (a broken Keystore on some devices). */
class DeviceStorageException(cause: Throwable) :
    Exception("This phone couldn't store your sign-in securely. Restart the phone and try again.", cause)

/**
 * Simple manual dependency container: holds the secure store, the HTTP client and the
 * current API client, and tracks whether the user is signed in and the vault unlocked.
 */
private const val SSO_FAILED = "Single sign-on didn't complete. Please try again."

class AppContainer(val context: Context) {
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val main = Handler(Looper.getMainLooper())

    val store = SecureStore(context)
    val vault = FileVault(context)
    val pendingSso = PendingSsoStore(context)

    /** A scanvault://sso callback that matched the sign-in in progress, consumed by [completeSso]. */
    val ssoCallbacks = MutableStateFlow<SsoResult?>(null)

    /** Message to show on the sign-in screen when SSO fails. */
    val ssoError = MutableStateFlow<String?>(null)

    /**
     * Starts SSO with [provider] on [server]: makes a PKCE pair and state, remembers them
     * (encrypted) and opens the server's start URL in a Custom Tab. https servers only.
     */
    fun startSso(activityContext: Context, server: String, provider: SsoProvider) {
        val base = ApiClient.normalizeBaseUrl(server)
        if (!base.isHttps) throw InsecureConnectionException("Single sign-on needs an https server address.")
        val verifier = Pkce.randomToken()
        val state = Pkce.randomToken()
        pendingSso.save(PendingSso(base.toString(), provider.name, state, verifier, System.currentTimeMillis()))
        ssoError.value = null
        val url = clientFor(base.toString()).ssoStartUrl(provider.id, PendingSso.REDIRECT, state, Pkce.challenge(verifier))
        appLock.expectExternalTrip()
        androidx.browser.customtabs.CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
            .launchUrl(activityContext, android.net.Uri.parse(url))
    }

    /**
     * Called for every scanvault://sso link that reaches the app. Any app or web page can open
     * that link, so it is accepted only while a sign-in this app started is pending and its
     * state matches; anything else is ignored and leaves the pending sign-in untouched.
     */
    fun offerSsoCallback(result: SsoResult) {
        val pending = pendingSso.load() ?: return
        val state = result.state ?: return
        if (!MessageDigest.isEqual(state.toByteArray(), pending.state.toByteArray())) return
        ssoCallbacks.value = result
    }

    /** Finishes SSO from a matching redirect: exchanges the ticket and signs in. */
    suspend fun completeSso(result: SsoResult) {
        val pending = pendingSso.load() ?: return
        if (result.state != pending.state) return
        pendingSso.clear()
        val outcome = runCatching {
            when (result) {
                is SsoResult.Cancelled -> return
                is SsoResult.Failed -> error(SSO_FAILED)
                is SsoResult.Ticket -> Unit
            }
            if (pending.expired) error("Single sign-on took too long. Please try again.")
            // Errors here come from the user's own server (the one the sign-in started on).
            val login = clientFor(pending.server).ssoExchange((result as SsoResult.Ticket).ticket, pending.verifier)
            val status = runCatching { clientFor(pending.server, login.token).status() }.getOrNull()
            onSignedIn(
                pending.server,
                status?.username ?: pending.providerName,
                login.token,
                unlocked = login.unlocked ?: status?.unlocked ?: false,
                expiresAt = login.expiresAt,
            )
        }
        outcome.onFailure { e ->
            ssoError.value = when (e) {
                is DeviceStorageException, is IllegalStateException -> e.message
                else -> e.userMessage()
            } ?: SSO_FAILED
        }
    }

    val pendingUploads = PendingUploads(context, vault)
    val appLock = AppLock { store.lockTimeoutMinutes }

    val theme = ThemeStore(context).also { theme ->
        theme.onChanged = { settings ->
            if (_session.value == SessionState.SignedOut) {
                theme.changedWhileSignedOut = true
            } else {
                appScope.launch { runCatching { pushTheme(settings) } }
            }
        }
    }

    private suspend fun pushTheme(settings: ThemeSettings) {
        api.savePrefs(ServerPrefs(theme = settings.mode.wire, darkColor = settings.darkColor))
    }

    /**
     * Brings the theme in line with the server after sign-in: a change made on this phone while
     * signed out wins and is pushed; otherwise the server's (shared with the web app) is applied.
     */
    fun syncThemeFromServer() {
        if (_session.value == SessionState.SignedOut) return
        appScope.launch {
            if (theme.changedWhileSignedOut) {
                runCatching { pushTheme(theme.settings.value) }.onSuccess { theme.changedWhileSignedOut = false }
            } else {
                runCatching { api.prefs() }.onSuccess { theme.applyServer(it) }
            }
        }
    }

    /** One client for API and images: system CAs + user-approved pins, LAN-only opt-in http, no redirects. */
    private val baseHttp: OkHttpClient = HttpClients.create({ store.allowLanHttp }, { store.certPins })

    private val _session = MutableStateFlow<SessionState>(
        if (store.serverUrl != null && store.token != null && !store.tokenExpired) SessionState.Ready
        else SessionState.SignedOut
    )
    val session: StateFlow<SessionState> = _session.asStateFlow()

    @Volatile private var cachedApi: ApiClient? = null

    val api: ApiClient
        get() {
            val url = store.serverUrl ?: error("No server configured")
            cachedApi?.let { if (it.url("").toString() == ApiClient.normalizeBaseUrl(url).toString()) return it }
            return ApiClient(url, { store.token }, baseHttp).also { cachedApi = it }
        }

    /**
     * Image loader that sends the bearer token, but only to the configured ScanVault host,
     * keeps decoded images in memory only, and reacts to a locked vault or an expired session
     * the same way API calls do.
     */
    val imageLoader: ImageLoader by lazy {
        val authed = baseHttp.newBuilder().addInterceptor { chain ->
            val req = chain.request()
            val server = store.serverUrl?.let { runCatching { ApiClient.normalizeBaseUrl(it) }.getOrNull() }
            val token = store.token
            val toServer = server != null && req.url.host == server.host && req.url.port == server.port
            val response = if (toServer && token != null) {
                chain.proceed(req.newBuilder().header("Authorization", "Bearer $token").build())
            } else {
                chain.proceed(req)
            }
            if (toServer) when (response.code) {
                423 -> main.post { markLocked() }
                401 -> main.post { signOut() }
            }
            response
        }.build()
        ImageLoader.Builder(context)
            .okHttpClient(authed)
            .diskCache(null as DiskCache?)
            .crossfade(true)
            .build()
    }

    /** Builds a throwaway client for a server the user has not saved yet (login screen). */
    fun clientFor(url: String, token: String? = null) = ApiClient(url, { token }, baseHttp)

    /** Saves a new session. Throws [DeviceStorageException] if the Keystore can't store it. */
    fun onSignedIn(url: String, username: String, token: String, unlocked: Boolean, expiresAt: String? = null) {
        try {
            store.serverUrl = ApiClient.normalizeBaseUrl(url).toString()
            store.username = username
            store.token = token
            store.tokenExpiresAt = expiresAt
        } catch (e: Exception) {
            runCatching { store.token = null }
            throw DeviceStorageException(e)
        }
        cachedApi = null
        appLock.unlock() // they just proved who they are by signing in
        _session.value = if (unlocked) SessionState.Ready else SessionState.Locked
    }

    fun markLocked() { if (_session.value != SessionState.SignedOut) _session.value = SessionState.Locked }

    fun markUnlocked() { if (_session.value != SessionState.SignedOut) _session.value = SessionState.Ready }

    /** Unlocks the server's vault, with the same 401 handling as every other call. */
    suspend fun unlockVault(passphrase: String? = null, recoveryKey: String? = null): Result<Unit> =
        call { it.unlock(passphrase, recoveryKey) }.onSuccess { markUnlocked() }

    /** Revokes the token on the server (best effort) and forgets it locally. */
    fun logout() {
        val url = store.serverUrl
        val token = store.token
        if (url != null && token != null) {
            appScope.launch { runCatching { clientFor(url, token).logout() } }
        }
        signOut()
    }

    fun signOut() {
        if (_session.value == SessionState.SignedOut && store.token == null) return
        runCatching { store.token = null }
        runCatching { store.tokenExpiresAt = null }
        cachedApi = null
        imageLoader.memoryCache?.clear()
        wipeFiles()
        _session.value = SessionState.SignedOut
    }

    /** Signs out locally once the server-issued expiry has passed. */
    fun checkExpiry() {
        if (_session.value != SessionState.SignedOut && store.tokenExpired) signOut()
    }

    /** Runs an API call and translates vault-locked / unauthorized errors into session changes. */
    suspend fun <T> call(block: suspend (ApiClient) -> T): Result<T> = try {
        Result.success(block(api))
    } catch (e: VaultLockedException) {
        markLocked(); Result.failure(e)
    } catch (e: UnauthorizedException) {
        signOut(); Result.failure(e)
    } catch (e: kotlinx.coroutines.CancellationException) {
        throw e
    } catch (e: Exception) {
        Result.failure(e)
    }

    /**
     * Where the system camera app writes a photo. It can only write plain files, so the app
     * encrypts each photo into the vault the moment the camera returns and deletes this copy.
     */
    fun captureDir(): File = File(context.cacheDir, "captures").apply { mkdirs() }

    /**
     * On launch: drop shared copies from the last run, plus camera files old enough that no
     * camera can still be writing them. A photo being taken right now (the app was killed while
     * the camera was open) is kept so it can still be saved when the camera returns.
     */
    fun cleanUpOnLaunch() {
        SecureFileProvider.revokeAll()
        vault.clear(FileVault.Area.SHARE)
        val cutoff = System.currentTimeMillis() - 60 * 60_000L
        File(context.cacheDir, "captures").listFiles()?.filter { it.lastModified() < cutoff }?.forEach { it.delete() }
        File(context.cacheDir, "shared").deleteRecursively() // plaintext copies from version 0.1.0
    }

    /** On sign-out: everything, including photos that never uploaded. */
    private fun wipeFiles() {
        SecureFileProvider.revokeAll()
        vault.clear(FileVault.Area.SHARE)
        pendingUploads.clear()
        File(context.cacheDir, "captures").deleteRecursively()
        File(context.cacheDir, "shared").deleteRecursively()
    }
}
