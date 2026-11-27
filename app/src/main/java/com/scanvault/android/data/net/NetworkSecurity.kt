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

/** Thrown before any byte is sent when a connection would be unencrypted and isn't allowed. */
class InsecureConnectionException(message: String) : IOException(message)

/**
 * The server's certificate isn't trusted by Android and hasn't been approved by the user.
 * [fingerprint] is the SHA-256 of the leaf certificate, for the user to compare and pin.
 */
class UntrustedCertificateException(val fingerprint: String, val subject: String) :
    CertificateException("Untrusted certificate $fingerprint")

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
class CleartextPolicyInterceptor(private val allowLanHttp: () -> Boolean) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.isHttps) return chain.proceed(request.newBuilder().removeHeader(SENSITIVE_HEADER).build())
        if (request.header(SENSITIVE_HEADER) != null) {
            throw InsecureConnectionException("The vault key is never sent over unencrypted http. Use an https address.")
        }
        if (!allowLanHttp()) {
            throw InsecureConnectionException(
                "This address uses unencrypted http. Use https, or allow http on your local network in the sign-in screen.",
            )
        }
        val address = chain.connection()?.route()?.socketAddress?.address
        if (address == null || !PrivateAddress.isPrivate(address)) {
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
 * Trusts the system CA store (never user-installed CAs in release builds), plus any leaf
 * certificate whose SHA-256 the user explicitly approved for their self-signed server
 * (trust on first use). Approving one is shown to the user with its fingerprint.
 */
class PinningTrustManager(private val pins: () -> Set<String>) : X509TrustManager {
    private val system: X509TrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        .apply { init(null as KeyStore?) }
        .trustManagers.filterIsInstance<X509TrustManager>().first()

    override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) =
        system.checkClientTrusted(chain, authType)

    override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
        try {
            system.checkServerTrusted(chain, authType)
        } catch (e: CertificateException) {
            val leaf = chain.firstOrNull() ?: throw e
            val fp = leaf.sha256Fingerprint()
            if (fp in pins()) {
                leaf.checkValidity()
                return
            }
            throw UntrustedCertificateException(fp, leaf.subjectX500Principal.name)
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = system.acceptedIssuers
}

/** Normal hostname checks, except a user-pinned certificate is accepted for the configured server. */
class PinningHostnameVerifier(private val pins: () -> Set<String>) : HostnameVerifier {
    override fun verify(hostname: String, session: SSLSession): Boolean {
        if (OkHostnameVerifier.verify(hostname, session)) return true
        val leaf = runCatching { session.peerCertificates.firstOrNull() as? X509Certificate }.getOrNull() ?: return false
        return leaf.sha256Fingerprint() in pins()
    }
}

object HttpClients {
    /**
     * The one HTTP client the app uses (API calls and image loading): system CAs plus user pins,
     * cleartext policy, and no redirects at all, so an https request can't be bounced to http
     * and a 307/308 can't re-post a password or vault key elsewhere.
     */
    fun create(allowLanHttp: () -> Boolean, pins: () -> Set<String>): OkHttpClient {
        val trust = PinningTrustManager(pins)
        val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
        return OkHttpClient.Builder()
            .sslSocketFactory(ssl.socketFactory, trust)
            .hostnameVerifier(PinningHostnameVerifier(pins))
            .addNetworkInterceptor(CleartextPolicyInterceptor(allowLanHttp))
            .followRedirects(false)
            .followSslRedirects(false)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.MINUTES)
            .writeTimeout(10, TimeUnit.MINUTES)
            .build()
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
