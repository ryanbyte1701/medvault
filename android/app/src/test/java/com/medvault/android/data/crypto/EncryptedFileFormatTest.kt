package com.medvault.android.data.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.Random
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class EncryptedFileFormatTest {
    @get:Rule val tmp = TemporaryFolder()

    private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val wrapped = byteArrayOf(9, 9, 9) // stands in for the Keystore-wrapped key
    private val unwrap: (ByteArray) -> SecretKey = { assertArrayEquals(wrapped, it); key }

    private fun bytes(n: Int) = ByteArray(n).also { Random(n.toLong()).nextBytes(it) }

    private fun write(data: ByteArray, chunk: Int = 1024, name: String = "f.sve"): File {
        val f = tmp.root.resolve(name)
        EncryptedFileFormat.Writer(f, key, wrapped, chunk).use { w ->
            // Write in odd-sized pieces to exercise buffering.
            var i = 0
            while (i < data.size) { val n = minOf(333, data.size - i); w.write(data, i, n); i += n }
        }
        return f
    }

    @Test fun roundTripsManySizes() {
        for (size in listOf(0, 1, 1023, 1024, 1025, 4096, 10_000)) {
            val data = bytes(size)
            val f = write(data)
            EncryptedFileFormat.Reader(f, unwrap).use { r ->
                assertEquals(size.toLong(), r.plaintextLength)
                assertArrayEquals("size $size", data, r.inputStream().readBytes())
            }
        }
    }

    @Test fun ciphertextDoesNotContainPlaintext() {
        val data = "PATIENT JANE DOE MRN 12345 ".repeat(200).toByteArray()
        val raw = write(data).readBytes()
        assertFalse(String(raw, Charsets.ISO_8859_1).contains("JANE DOE"))
        assertTrue(EncryptedFileFormat.looksEncrypted(tmp.root.resolve("f.sve")))
    }

    @Test fun randomAccessReadsAcrossChunks() {
        val data = bytes(5000)
        EncryptedFileFormat.Reader(write(data), unwrap).use { r ->
            val buf = ByteArray(2500)
            assertEquals(2500, r.read(1000, 2500, buf))
            assertArrayEquals(data.copyOfRange(1000, 3500), buf)
            assertEquals(100, r.read(4900, 2500, buf))
            assertEquals(0, r.read(5000, 10, buf))
        }
    }

    @Test fun tamperedByteIsDetected() {
        val f = write(bytes(3000))
        RandomAccessFile(f, "rw").use { it.seek(f.length() - 40); val b = it.read(); it.seek(f.length() - 40); it.write(b xor 1) }
        expectIntegrityFailure(f)
    }

    @Test fun truncationIsDetected() {
        val f = write(bytes(3000))
        // Drop the whole last chunk and shrink the stored length to match: the new last chunk
        // was not written as "last", so authentication fails.
        RandomAccessFile(f, "rw").use { raf ->
            raf.seek(9); raf.writeLong(2048)
            raf.setLength(f.length() - (12 + (3000 - 2048) + 16))
        }
        expectIntegrityFailure(f)
    }

    @Test fun headerLengthCannotBeZeroedToReadAsEmpty() {
        val f = write(bytes(500))
        RandomAccessFile(f, "rw").use { raf -> raf.seek(9); raf.writeLong(0) }
        expectIntegrityFailure(f)
    }

    @Test fun headerChunkSizeIsAuthenticated() {
        val f = write(bytes(3000))
        RandomAccessFile(f, "rw").use { raf -> raf.seek(5); raf.writeInt(2048) }
        expectIntegrityFailure(f)
    }

    @Test fun chunksCannotBeSwappedBetweenFiles() {
        val a = write(bytes(2048), name = "a.sve")
        val b = write(bytes(2049), name = "b.sve")
        // Copy b's first chunk over a's first chunk (same position and size).
        val header = 4 + 1 + 4 + 8 + 16 + 2 + wrapped.size
        val chunk = 12 + 1024 + 16
        val bChunk = ByteArray(chunk).also { RandomAccessFile(b, "r").use { r -> r.seek(header.toLong()); r.readFully(it) } }
        RandomAccessFile(a, "rw").use { it.seek(header.toLong()); it.write(bChunk) }
        expectIntegrityFailure(a)
    }

    private fun expectIntegrityFailure(f: File) {
        try {
            EncryptedFileFormat.Reader(f, unwrap).use { it.inputStream().readBytes() }
            fail("expected an integrity failure")
        } catch (e: IOException) {
            // expected
        }
    }
}
