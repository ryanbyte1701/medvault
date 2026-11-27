package com.medvault.android.data.crypto

import android.content.Context
import java.io.File
import java.io.InputStream
import java.util.UUID
import javax.crypto.KeyGenerator

/**
 * Encrypted on-disk storage for files the app has to keep: reports opened in other apps
 * ([Area.SHARE], wiped on every launch) and camera photos waiting to upload ([Area.PENDING],
 * kept until they upload or the user discards them, and wiped on sign-out). Files are named by
 * random ids, so not even names or file types are visible on disk.
 */
class FileVault(context: Context) {
    enum class Area(val dir: String) { SHARE("vault"), PENDING("pending") }

    private val root = context.cacheDir
    private val pendingRoot = File(context.noBackupFilesDir, "pending")

    private fun dirFor(area: Area) = when (area) {
        Area.SHARE -> File(root, area.dir)
        Area.PENDING -> pendingRoot
    }.apply { mkdirs() }

    data class Entry(val id: String, val file: File)

    private fun newDataKey() = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    /** Encrypts [input] into a new vault file. The stream is fully consumed but not closed. */
    fun store(input: InputStream, area: Area = Area.SHARE): Entry {
        val id = UUID.randomUUID().toString()
        val file = File(dirFor(area), "$id.sve")
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

    fun find(id: String, area: Area = Area.SHARE): Entry? =
        File(dirFor(area), "$id.sve").takeIf { it.exists() }?.let { Entry(id, it) }

    fun delete(entry: Entry) { entry.file.delete() }

    /** Deletes shared copies older than [maxAgeMillis] (other apps have long finished reading them). */
    fun pruneShared(maxAgeMillis: Long) {
        val cutoff = System.currentTimeMillis() - maxAgeMillis
        dirFor(Area.SHARE).listFiles()?.filter { it.lastModified() < cutoff }?.forEach { it.delete() }
    }

    fun clear(area: Area) {
        dirFor(area).listFiles()?.forEach { it.delete() }
    }

    fun clearAll() = Area.entries.forEach(::clear)
}
