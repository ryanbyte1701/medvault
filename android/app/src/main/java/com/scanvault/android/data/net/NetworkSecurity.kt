package com.scanvault.android.data.net

import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.internal.tls.OkHostnameVerifier
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import java.net.Socket

/** Thrown before any byte is sent when a connection would be unencrypted and isn't allowed. */
class InsecureConnectionException(message: String) : IOException(message)

/**
 * The server's certificate isn't trusted by Android and hasn't been approved by the user.
 * [fingerprint] is the SHA-256 of the leaf certificate, for the user to compare and pin.
 */
class UntrustedCertificateException(
    val fingerprint: String,
    val subject: String,
    val host: String? = null,
    val port: Int = -1,
) : CertificateException("Untrusted certificate $fingerprint") {
    /** What to store to trust this certificate for this server only, or null if the server is unknown. */
    val pinKey: String? get() = host?.let { CertPins.key(it, port, fingerprint) }
}

/** Approved self-signed certificates are stored per server as "host:port SHA256". */
object CertPins {
    fun key(host: String, port: Int, fingerprint: String) = "${host.lowercase()}:$port $fingerprint"
}

object PrivateAddress {
    /** Loopback, RFC 1918, link-local, CGNAT/Tailscale (100.64/10) and IPv6 ULA (fc00::/7). */
    fun isPrivate(address: InetAddress): Boolean {
        if (address.isLoopbackAddress || address.isLinkLocalAddress || address.isSiteLocalAddress) return true
        val b = address.address
        return when (address) {
            is Inet4Address -> (b[0].toInt() and 0xFF) == 100 && (b[1].toInt() and 0xC0) == 64
            is Inet6Address -> (b[0].toInt() and 0xFE) == 0xFC
            else -> false
        }
    }
}

/**
 * Network interceptor enforcing the app's cleartext policy at the moment of connection:
 * plain http is refused unless the user opted in for their local network, and even then only
 * when the address actually connected to is private. Requests marked [SENSITIVE_HEADER]
 * (vault unlock) are never allowed over http.
 */
class CleartextPolicyInterceptor(private val allowLanHttp: (host: String) -> Boolean) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.isHttps) return chain.proceed(request.newBuilder().removeHeader(SENSITIVE_HEADER).build())
        if (request.header(SENSITIVE_HEADER) != null) {
            throw InsecureConnectionException("The vault key is never sent over unencrypted http. Use an https address.")
        }
        if (!allowLanHttp(request.url.host)) {
            throw InsecureConnectionException(
                "This address uses unencrypted http. Use https, or allow http on your local network in the sign-in screen.",
            )
        }
        val route = chain.connection()?.route()
        val address = route?.socketAddress?.address
        // A direct connection only: through a proxy, the private address checked would be the
        // proxy's, not the server's.
        if (route == null || route.proxy.type() != java.net.Proxy.Type.DIRECT ||
            address == null || !PrivateAddress.isPrivate(address)) {
            throw InsecureConnectionException("Unencrypted http is only allowed to addresses on your local network.")
        }
        return chain.proceed(request)
    }

    companion object {
        /** Marker header for requests that carry key material; stripped before sending. */
        const val SENSITIVE_HEADER = "X-ScanVault-Sensitive"
    }
}

fun X509Certificate.sha256Fingerprint(): String =
    MessageDigest.getInstance("SHA-256").digest(encoded).joinToString(":") { "%02X".format(it) }

/**
 * Trusts the system CA store (never user-installed CAs in release builds), plus a leaf
 * certificate the user explicitly approved for this exact server (host and port), after being
 * shown its SHA-256 fingerprint (trust on first use).
 */
class PinningTrustManager(private val pins: () -> Set<String>) : X509ExtendedTrustManager() {
    private val system: X509TrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        .apply { init(null as KeyStore?) }
        .trustManagers.filterIsInstance<X509TrustManager>().first()

    override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) =
        system.checkClientTrusted(chain, authType)
    override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String, socket: Socket?) =
        system.checkClientTrusted(chain, authType)
    override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String, engine: SSLEngine?) =
        system.checkClientTrusted(chain, authType)

    // Without a socket there is no way to tell which server this is, so no pin can apply.
    override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) =
        check(chain, authType, null, -1)

    override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String, socket: Socket?) {
        val session = (socket as? SSLSocket)?.handshakeSession
        check(chain, authType, session?.peerHost ?: (socket as? SSLSocket)?.inetAddress?.hostName, session?.peerPort ?: socket?.port ?: -1)
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String, engine: SSLEngine?) =
        check(chain, authType, engine?.peerHost, engine?.peerPort ?: -1)

    private fun check(chain: Array<out X509Certificate>, authType: String, host: String?, port: Int) {
        try {
            system.checkServerTrusted(chain, authType)
        } catch (e: CertificateException) {
            val leaf = chain.firstOrNull() ?: throw e
            val fp = leaf.sha256Fingerprint()
            if (host != null && CertPins.key(host, port, fp) in pins()) {
                leaf.checkValidity()
                return
            }
            throw UntrustedCertificateException(fp, leaf.subjectX500Principal.name, host, port)
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = system.acceptedIssuers
}

/** Normal hostname checks, except a certificate the user pinned for this host and port. */
class PinningHostnameVerifier(private val pins: () -> Set<String>) : HostnameVerifier {
    override fun verify(hostname: String, session: SSLSession): Boolean {
        if (OkHostnameVerifier.verify(hostname, session)) return true
        val leaf = runCatching { session.peerCertificates.firstOrNull() as? X509Certificate }.getOrNull() ?: return false
        return CertPins.key(hostname, session.peerPort, leaf.sha256Fingerprint()) in pins()
    }
}

object HttpClients {
    /**
     * The one HTTP client the app uses (API calls and image loading): system CAs plus user pins,
     * cleartext policy, and no redirects at all, so an https request can't be bounced to http
     * and a 307/308 can't re-post a password or vault key elsewhere.
     */
    fun create(allowLanHttp: (host: String) -> Boolean, pins: () -> Set<String>): OkHttpClient {
        val trust = PinningTrustManager(pins)
        val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
        return OkHttpClient.Builder()
            .sslSocketFactory(ssl.socketFactory, trust)
            .hostnameVerifier(PinningHostnameVerifier(pins))
            .addInterceptor { chain -> chain.proceed(chain.request().newBuilder().header("User-Agent", USER_AGENT).build()) }
            .addNetworkInterceptor(CleartextPolicyInterceptor(allowLanHttp))
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.MINUTES)
            .writeTimeout(10, TimeUnit.MINUTES)
            .build()
    }

    /** Lets the server's activity log show "Android app" and the app version for this device's requests. */
    val USER_AGENT: String by lazy {
        val release = runCatching { android.os.Build.VERSION.RELEASE }.getOrNull()
        val model = runCatching { android.os.Build.MODEL }.getOrNull()
        "ScanVault-Android/${com.scanvault.android.BuildConfig.VERSION_NAME}" +
            listOfNotNull(model?.takeIf { it.isNotBlank() }, release?.takeIf { it.isNotBlank() }?.let { "Android $it" })
                .takeIf { it.isNotEmpty() }?.joinToString("; ", " (", ")").orEmpty()
    }

    /** Finds an [UntrustedCertificateException] anywhere in a failure's cause chain. */
    fun untrustedCertificate(error: Throwable): UntrustedCertificateException? {
        var e: Throwable? = error
        repeat(8) {
            if (e is UntrustedCertificateException) return e as UntrustedCertificateException
            e = e?.cause ?: return null
        }
        return null
    }
}
