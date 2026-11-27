package com.scanvault.android.data

import android.content.Context
import coil.ImageLoader
import coil.disk.DiskCache
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import okhttp3.OkHttpClient
import com.scanvault.android.data.crypto.FileVault
import com.scanvault.android.data.crypto.SecureFileProvider
import java.io.File

/** Session-level state shared by every screen. */
sealed interface SessionState {
    data object SignedOut : SessionState
    data object Ready : SessionState
    data object Locked : SessionState
}

/**
 * Simple manual dependency container: holds the secure store, the HTTP client and the
 * current API client, and tracks whether the user is signed in and the vault unlocked.
 */
class AppContainer(val context: Context) {
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    val store = SecureStore(context)
    val vault = FileVault(context)
    val pendingSso = PendingSsoStore(context)

    /** The latest scanvault://sso callback, consumed by [completeSso]. */
    val ssoCallbacks = MutableStateFlow<SsoResult?>(null)

    /** Message to show on the sign-in screen when SSO fails. */
    val ssoError = MutableStateFlow<String?>(null)

    /**
     * Starts SSO with [provider] on [server]: makes a PKCE pair and state, remembers them
     * (encrypted) and opens the server's start URL in a Custom Tab.
     */
    fun startSso(activityContext: Context, server: String, provider: SsoProvider) {
        val verifier = Pkce.randomToken()
        val state = Pkce.randomToken()
        val base = ApiClient.normalizeBaseUrl(server).toString()
        pendingSso.save(PendingSso(base, provider.name, state, verifier, System.currentTimeMillis()))
        ssoError.value = null
        val url = clientFor(base).ssoStartUrl(provider.id, PendingSso.REDIRECT, state, Pkce.challenge(verifier))
        androidx.browser.customtabs.CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
            .launchUrl(activityContext, android.net.Uri.parse(url))
    }

    /** Finishes SSO from the browser's redirect: checks state, exchanges the ticket, signs in. */
    suspend fun completeSso(result: SsoResult) {
        val pending = pendingSso.load()
        pendingSso.clear()
        val outcome = runCatching {
            val p = pending ?: error("No sign-in was in progress. Please try again.")
            val returnedState = when (result) {
                is SsoResult.Ticket -> result.state
                is SsoResult.Error -> result.state
            }
            if (returnedState != p.state) error("The sign-in response didn't match this request. Please try again.")
            if (result is SsoResult.Error) error(result.message)
            if (p.expired) error("Single sign-on took too long. Please try again.")
            val ticket = (result as SsoResult.Ticket).ticket
            val login = clientFor(p.server).ssoExchange(ticket, p.verifier)
            val status = runCatching { clientFor(p.server, login.token).status() }.getOrNull()
            onSignedIn(
                p.server,
                status?.username ?: p.providerName,
                login.token,
                unlocked = login.unlocked ?: status?.unlocked ?: true,
            )
        }
        outcome.onFailure { e ->
            ssoError.value = (e as? ApiException)?.message ?: e.message ?: "Single sign-on failed"
        }
    }
    val theme = ThemeStore(context).also { store ->
        store.onChanged = { settings ->
            if (_session.value != SessionState.SignedOut) {
                appScope.launch {
                    runCatching {
                        api.savePrefs(ServerPrefs(theme = settings.mode.wire, darkColor = settings.darkColor))
                    }
                }
            }
        }
    }

    /** Pulls the user's theme from the server so it matches the web app. Best effort. */
    fun syncThemeFromServer() {
        if (_session.value == SessionState.SignedOut) return
        appScope.launch { runCatching { api.prefs() }.onSuccess { theme.applyServer(it) } }
    }

    private val baseHttp: OkHttpClient = ApiClient.defaultHttpClient()

    private val _session = MutableStateFlow<SessionState>(
        if (store.serverUrl != null && store.token != null) SessionState.Ready else SessionState.SignedOut
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
     * and keeps decoded thumbnails in memory only (no PHI written to a disk cache).
     */
    val imageLoader: ImageLoader by lazy {
        val authed = baseHttp.newBuilder().addInterceptor { chain ->
            val req = chain.request()
            val server = store.serverUrl?.let { runCatching { ApiClient.normalizeBaseUrl(it) }.getOrNull() }
            val token = store.token
            if (server != null && token != null && req.url.host == server.host && req.url.port == server.port) {
                chain.proceed(req.newBuilder().header("Authorization", "Bearer $token").build())
            } else {
                chain.proceed(req)
            }
        }.build()
        ImageLoader.Builder(context)
            .okHttpClient(authed)
            .diskCache(null as DiskCache?)
            .crossfade(true)
            .build()
    }

    /** Builds a throwaway client for a server the user has not saved yet (login screen). */
    fun clientFor(url: String, token: String? = null) = ApiClient(url, { token }, baseHttp)

    fun onSignedIn(url: String, username: String, token: String, unlocked: Boolean) {
        store.serverUrl = ApiClient.normalizeBaseUrl(url).toString()
        store.username = username
        store.token = token
        cachedApi = null
        _session.value = if (unlocked) SessionState.Ready else SessionState.Locked
    }

    fun markLocked() { if (_session.value != SessionState.SignedOut) _session.value = SessionState.Locked }

    fun markUnlocked() { if (_session.value != SessionState.SignedOut) _session.value = SessionState.Ready }

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
        store.token = null
        cachedApi = null
        imageLoader.memoryCache?.clear()
        clearSharedCache()
        _session.value = SessionState.SignedOut
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

    /** Wipes every file the app has written: the encrypted vault, camera leftovers, old plaintext caches. */
    fun clearSharedCache() {
        SecureFileProvider.revokeAll()
        vault.clear()
        File(context.cacheDir, "captures").deleteRecursively()
        File(context.cacheDir, "shared").deleteRecursively() // plaintext copies from version 0.1.0
    }
}
