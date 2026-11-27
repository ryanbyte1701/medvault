package com.scanvault.android.data.net

import com.scanvault.android.data.ApiClient
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.net.InetAddress

class NetworkSecurityTest {
    private lateinit var server: MockWebServer
    private var allowHttp = false

    @Before fun setUp() { server = MockWebServer().apply { start() } }
    @After fun tearDown() { server.shutdown() }

    private fun api() = ApiClient(server.url("/").toString(), { "tok" }, HttpClients.create({ allowHttp }, { emptySet() }))

    @Test fun privateAddressRanges() {
        listOf("127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.20", "169.254.1.1", "100.100.1.1", "::1", "fd12::1")
            .forEach { assertTrue(it, PrivateAddress.isPrivate(InetAddress.getByName(it))) }
        listOf("8.8.8.8", "1.1.1.1", "100.128.0.1", "172.32.0.1", "2001:4860::8888")
            .forEach { assertFalse(it, PrivateAddress.isPrivate(InetAddress.getByName(it))) }
    }

    @Test fun httpIsRefusedUnlessOptedIn() = runTest {
        server.enqueue(MockResponse().setBody("[]"))
        try { api().patients(); fail("expected refusal") } catch (e: InsecureConnectionException) { }
        assertEquals("nothing may be sent", 0, server.requestCount)
    }

    @Test fun httpToLocalAddressWorksWhenOptedIn() = runTest {
        allowHttp = true
        server.enqueue(MockResponse().setBody("[]"))
        assertEquals(0, api().patients().size)
    }

    @Test fun httpOptInIsBoundToItsHost() = runTest {
        server.enqueue(MockResponse().setBody("[]"))
        val other = ApiClient(server.url("/").toString(), { "tok" },
            HttpClients.create({ host -> host == "nas.local" }, { emptySet() }))
        try { other.patients(); fail("expected refusal") } catch (e: InsecureConnectionException) { }
        assertEquals(0, server.requestCount)
    }

    @Test fun vaultKeyIsNeverSentOverHttpEvenWhenOptedIn() = runTest {
        allowHttp = true
        try { api().unlock(passphrase = "secret"); fail("expected refusal") } catch (e: InsecureConnectionException) { }
        assertEquals(0, server.requestCount)
    }

    @Test fun redirectsAreNotFollowed() = runTest {
        allowHttp = true
        server.enqueue(MockResponse().setResponseCode(307).setHeader("Location", "http://example.com/steal"))
        try { api().login("u", "p"); fail("expected an error") } catch (e: Exception) { }
        assertEquals(1, server.requestCount)
    }

    @Test fun findsUntrustedCertificateInCauseChain() {
        val inner = UntrustedCertificateException("AA:BB", "CN=nas")
        val outer = javax.net.ssl.SSLHandshakeException("handshake").apply { initCause(RuntimeException(inner)) }
        assertEquals("AA:BB", HttpClients.untrustedCertificate(outer)?.fingerprint)
    }
}

class CertificatePinningTest {
    private val cert = okhttp3.tls.HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
    private val server = MockWebServer().apply {
        useHttps(okhttp3.tls.HandshakeCertificates.Builder().heldCertificate(cert).build().sslSocketFactory(), false)
        start()
    }
    private val url = server.url("/").newBuilder().host("localhost").build().toString()

    @After fun tearDown() = server.shutdown()

    @Test fun selfSignedIsRejectedWithItsFingerprintUntilPinned() = runTest {
        var pins = emptySet<String>()
        val api = ApiClient(url, { null }, HttpClients.create({ false }, { pins }))
        val untrusted = checkNotNull(
            try {
                api.status(); fail("expected untrusted"); null
            } catch (e: Exception) {
                HttpClients.untrustedCertificate(e)
            },
        )
        assertEquals(cert.certificate.sha256Fingerprint(), untrusted.fingerprint)
        assertEquals(CertPins.key("localhost", server.port, untrusted.fingerprint), untrusted.pinKey)
        assertEquals(0, server.requestCount)

        pins = setOf(untrusted.pinKey!!)
        server.enqueue(MockResponse().setBody("""{"unlocked":true}"""))
        assertTrue(api.status().unlocked)
    }

    @Test fun aPinOnlyAppliesToItsOwnHostAndPort() = runTest {
        val fp = cert.certificate.sha256Fingerprint()
        val pins = setOf(CertPins.key("localhost", server.port + 1, fp), CertPins.key("nas.local", server.port, fp))
        val api = ApiClient(url, { null }, HttpClients.create({ false }, { pins }))
        try { api.status(); fail("pin for another server must not apply") } catch (e: Exception) {
            assertTrue(HttpClients.untrustedCertificate(e) != null)
        }
        assertEquals(0, server.requestCount)
    }
}
