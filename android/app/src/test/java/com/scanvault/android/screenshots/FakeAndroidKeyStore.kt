package com.scanvault.android.screenshots

import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStoreSpi
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Robolectric has no AndroidKeyStore. For the screenshot tests only, this registers a provider
 * with that name that keeps software AES keys in memory, so the app's encrypted preferences work.
 */
object FakeAndroidKeyStore {
    internal val keys = ConcurrentHashMap<String, SecretKey>()

    fun install() {
        if (Security.getProvider("AndroidKeyStore") is FakeProvider) return
        Security.removeProvider("AndroidKeyStore")
        Security.insertProviderAt(FakeProvider(), 1)
    }

    class FakeProvider : Provider("AndroidKeyStore", 1.0, "In-memory AndroidKeyStore for tests") {
        init {
            put("KeyStore.AndroidKeyStore", FakeKeyStore::class.java.name)
            put("KeyGenerator.AES", FakeKeyGenerator::class.java.name)
        }
    }

    class FakeKeyStore : KeyStoreSpi() {
        override fun engineGetKey(alias: String, password: CharArray?): Key? = keys[alias]
        override fun engineGetCertificateChain(alias: String): Array<Certificate>? = null
        override fun engineGetCertificate(alias: String): Certificate? = null
        override fun engineGetCreationDate(alias: String): Date? = if (keys.containsKey(alias)) Date() else null
        override fun engineSetKeyEntry(alias: String, key: Key, password: CharArray?, chain: Array<out Certificate>?) {
            keys[alias] = key as SecretKey
        }
        override fun engineSetKeyEntry(alias: String, key: ByteArray, chain: Array<out Certificate>?) =
            throw UnsupportedOperationException()
        override fun engineSetCertificateEntry(alias: String, cert: Certificate) = throw UnsupportedOperationException()
        override fun engineDeleteEntry(alias: String) { keys.remove(alias) }
        override fun engineAliases(): Enumeration<String> = Collections.enumeration(keys.keys.toList())
        override fun engineContainsAlias(alias: String) = keys.containsKey(alias)
        override fun engineSize() = keys.size
        override fun engineIsKeyEntry(alias: String) = keys.containsKey(alias)
        override fun engineIsCertificateEntry(alias: String) = false
        override fun engineGetCertificateAlias(cert: Certificate): String? = null
        override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit
        override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit
    }

    class FakeKeyGenerator : KeyGeneratorSpi() {
        private var alias: String? = null
        private val random = SecureRandom()

        override fun engineInit(random: SecureRandom?) = Unit
        override fun engineInit(keysize: Int, random: SecureRandom?) = Unit
        override fun engineInit(params: AlgorithmParameterSpec?, random: SecureRandom?) {
            // KeyGenParameterSpec, read reflectively so this class doesn't depend on the sandbox's copy.
            alias = params?.javaClass?.getMethod("getKeystoreAlias")?.invoke(params) as String?
        }

        override fun engineGenerateKey(): SecretKey {
            val key = SecretKeySpec(ByteArray(32).also(random::nextBytes), "AES")
            alias?.let { keys[it] = key }
            return key
        }
    }
}
