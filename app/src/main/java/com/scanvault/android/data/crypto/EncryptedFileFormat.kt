package com.scanvault.android.data.crypto

import java.io.DataInputStream
import java.io.EOFException
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Chunked AES-256-GCM file format used for everything the app writes to disk.
 *
 * Layout:
 * ```
 * "SVE1" | version u8 | chunkSize u32 | plaintextLength u64 | fileNonce[16] | wrappedKeyLen u16 | wrappedKey[n]
 * chunk 0 .. chunk k-1, each: nonce[12] | ciphertext(len) | tag[16]
 * ```
 * Each file has its own random data key, stored only wrapped (encrypted) by a non-exportable
 * Android Keystore key. Every chunk is authenticated with
 * AAD = SHA-256(header without length) | chunkIndex | isLast [| plaintextLength on the last chunk],
 * so the header (chunk size, wrapped key, nonce) and the total length are authenticated too, and
 * chunks can't be reordered, swapped between files or truncated without detection.
 * Fixed-size chunks allow random access, which lets other apps read a file through a seekable
 * proxy descriptor without a decrypted copy ever touching storage.
 */
object EncryptedFileFormat {
    const val DEFAULT_CHUNK_SIZE = 64 * 1024
    private val MAGIC = byteArrayOf('S'.code.toByte(), 'V'.code.toByte(), 'E'.code.toByte(), '1'.code.toByte())
    private const val VERSION: Byte = 2
    private const val NONCE_LEN = 12
    private const val TAG_LEN = 16
    private const val FILE_NONCE_LEN = 16
    private const val LENGTH_OFFSET = 4 + 1 + 4
    private val random = SecureRandom()

    /** SHA-256 over every header field except the length, which is only known at the end. */
    internal fun headerHash(chunkSize: Int, fileNonce: ByteArray, wrappedKey: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(
            ByteBuffer.allocate(4 + 1 + 4 + FILE_NONCE_LEN + 2 + wrappedKey.size)
                .put(MAGIC).put(VERSION).putInt(chunkSize).put(fileNonce)
                .putShort(wrappedKey.size.toShort()).put(wrappedKey).array(),
        )

    internal fun aad(headerHash: ByteArray, index: Long, last: Boolean, plaintextLength: Long): ByteArray {
        val b = ByteBuffer.allocate(headerHash.size + 8 + 1 + if (last) 8 else 0)
            .put(headerHash).putLong(index).put(if (last) 1 else 0)
        if (last) b.putLong(plaintextLength)
        return b.array()
    }

    /** Streams plaintext into [file] as an encrypted file. Close it to finish the file. */
    class Writer(
        private val file: File,
        private val dataKey: SecretKey,
        wrappedKey: ByteArray,
        private val chunkSize: Int = DEFAULT_CHUNK_SIZE,
    ) : OutputStream() {
        private val raf = RandomAccessFile(file, "rw").apply { setLength(0) }
        private val fileNonce = ByteArray(FILE_NONCE_LEN).also { random.nextBytes(it) }
        private val buffer = ByteArray(chunkSize)
        private var pos = 0
        private var index = 0L
        private var total = 0L
        private var closed = false
        private val hash: ByteArray

        init {
            require(wrappedKey.size <= 0xFFFF)
            hash = headerHash(chunkSize, fileNonce, wrappedKey)
            val header = ByteBuffer.allocate(LENGTH_OFFSET + 8 + FILE_NONCE_LEN + 2 + wrappedKey.size)
                .put(MAGIC).put(VERSION).putInt(chunkSize).putLong(0L).put(fileNonce)
                .putShort(wrappedKey.size.toShort()).put(wrappedKey)
            raf.write(header.array())
        }

        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) {
            check(!closed) { "closed" }
            var o = off
            var remaining = len
            while (remaining > 0) {
                if (pos == chunkSize) emit(last = false) // only emit once we know more data follows
                val n = minOf(remaining, chunkSize - pos)
                System.arraycopy(b, o, buffer, pos, n)
                pos += n; o += n; remaining -= n; total += n
            }
        }

        private fun emit(last: Boolean) {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val nonce = ByteArray(NONCE_LEN).also { random.nextBytes(it) }
            cipher.init(Cipher.ENCRYPT_MODE, dataKey, GCMParameterSpec(TAG_LEN * 8, nonce))
            cipher.updateAAD(aad(hash, index, last, total))
            raf.write(nonce)
            raf.write(cipher.doFinal(buffer, 0, pos))
            index++
            pos = 0
        }

        override fun close() {
            if (closed) return
            try {
                emit(last = true)
                raf.seek(LENGTH_OFFSET.toLong())
                raf.writeLong(total)
                raf.fd.sync()
            } finally {
                closed = true
                raf.close()
            }
        }

        /** Abandons a partial file. */
        fun abort() {
            closed = true
            runCatching { raf.close() }
            file.delete()
        }
    }

    /** Random-access reader. [unwrapKey] turns the stored wrapped key back into the data key. */
    class Reader(file: File, unwrapKey: (ByteArray) -> SecretKey) : AutoCloseable {
        private val raf = RandomAccessFile(file, "r")
        val chunkSize: Int
        val plaintextLength: Long
        private val fileNonce = ByteArray(FILE_NONCE_LEN)
        private val dataStart: Long
        private val hash: ByteArray
        private val key: SecretKey
        private val chunkCount: Long
        private var cachedIndex = -1L
        private var cached = ByteArray(0)

        init {
            try {
                val magic = ByteArray(4).also { raf.readFully(it) }
                if (!magic.contentEquals(MAGIC)) throw IOException("Not a ScanVault encrypted file")
                if (raf.readByte() != VERSION) throw IOException("Unsupported encrypted file version")
                chunkSize = raf.readInt()
                plaintextLength = raf.readLong()
                if (chunkSize <= 0 || plaintextLength < 0) throw IOException("Corrupt header")
                raf.readFully(fileNonce)
                val wrapped = ByteArray(raf.readUnsignedShort()).also { raf.readFully(it) }
                hash = headerHash(chunkSize, fileNonce, wrapped)
                dataStart = raf.filePointer
                key = unwrapKey(wrapped)
                chunkCount = maxOf(1L, (plaintextLength + chunkSize - 1) / chunkSize)
            } catch (e: Exception) {
                raf.close(); throw e
            }
        }

        private fun chunk(index: Long): ByteArray {
            if (index == cachedIndex) return cached
            val plainLen = if (index == chunkCount - 1) (plaintextLength - index * chunkSize).toInt() else chunkSize
            val stored = NONCE_LEN + plainLen + TAG_LEN
            raf.seek(dataStart + index * (NONCE_LEN + chunkSize + TAG_LEN).toLong())
            val bytes = ByteArray(stored)
            try { raf.readFully(bytes) } catch (e: EOFException) { throw IOException("Encrypted file is truncated", e) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_LEN * 8, bytes, 0, NONCE_LEN))
            cipher.updateAAD(aad(hash, index, index == chunkCount - 1, plaintextLength))
            cached = try {
                cipher.doFinal(bytes, NONCE_LEN, stored - NONCE_LEN)
            } catch (e: GeneralSecurityException) {
                throw IOException("Encrypted file failed its integrity check", e)
            }
            cachedIndex = index
            return cached
        }

        /** Reads up to [size] plaintext bytes at [offset] into [dest]; returns bytes read (0 at end). */
        @Synchronized
        fun read(offset: Long, size: Int, dest: ByteArray, destOffset: Int = 0): Int {
            if (offset >= plaintextLength || size <= 0) return 0
            var copied = 0
            var at = offset
            val end = minOf(plaintextLength, offset + size)
            while (at < end) {
                val idx = at / chunkSize
                val data = chunk(idx)
                val within = (at - idx * chunkSize).toInt()
                val n = minOf(data.size - within, (end - at).toInt())
                System.arraycopy(data, within, dest, destOffset + copied, n)
                copied += n; at += n
            }
            return copied
        }

        fun inputStream(): InputStream = object : InputStream() {
            private var position = 0L
            override fun read(): Int {
                val one = ByteArray(1)
                return if (read(one, 0, 1) == 1) one[0].toInt() and 0xFF else -1
            }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                val n = this@Reader.read(position, len, b, off)
                if (n == 0) return if (len == 0) 0 else -1
                position += n
                return n
            }
            override fun available(): Int = minOf(Int.MAX_VALUE.toLong(), plaintextLength - position).toInt()
            override fun close() = this@Reader.close()
        }

        override fun close() = raf.close()
    }

    /** True if [file] starts with this format's magic bytes. */
    fun looksEncrypted(file: File): Boolean = runCatching {
        DataInputStream(file.inputStream()).use { val m = ByteArray(4); it.readFully(m); m.contentEquals(MAGIC) }
    }.getOrDefault(false)
}
