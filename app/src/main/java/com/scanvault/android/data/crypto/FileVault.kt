package com.scanvault.android.data.crypto

import android.content.Context
import java.io.File
import java.io.InputStream
import java.util.UUID
import javax.crypto.KeyGenerator

/**
 * Encrypted on-disk storage for files the app has to keep briefly: downloaded reports opened in
 * other apps, and camera photos waiting to upload. Files are named by random ids, so not even
 * names or file types are visible on disk. The whole vault is wiped on launch and on sign-out.
 */
class FileVault(context: Context) {
    private val dir = File(context.cacheDir, "vault").apply { mkdirs() }

    data class Entry(val id: String, val file: File)

    private fun newDataKey() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    /** Encrypts [input] into a new vault file. The stream is fully consumed but not closed. */
    fun store(input: InputStream): Entry {
        val id = UUID.randomUUID().toString()
        val file = File(dir, "$id.sve")
        val key = newDataKey()
        val writer = EncryptedFileFormat.Writer(file, key, Keystore.wrapDataKey(key))
        try {
            input.copyTo(writer, 64 * 1024)
            writer.close()
        } catch (e: Throwable) {
            writer.abort(); throw e
        }
        return Entry(id, file)
    }

    /** Opens a random-access decrypting reader. Close it when done. */
    fun reader(entry: Entry): EncryptedFileFormat.Reader = reader(entry.file)

    fun reader(file: File): EncryptedFileFormat.Reader = EncryptedFileFormat.Reader(file, Keystore::unwrapDataKey)

    fun find(id: String): Entry? = File(dir, "$id.sve").takeIf { it.exists() }?.let { Entry(id, it) }

    fun delete(entry: Entry) { entry.file.delete() }

    fun clear() {
        dir.listFiles()?.forEach { it.delete() }
    }
}
