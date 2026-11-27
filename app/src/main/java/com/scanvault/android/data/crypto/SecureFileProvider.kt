package com.scanvault.android.data.crypto

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.provider.OpenableColumns
import android.system.ErrnoException
import android.system.OsConstants
import java.io.FileNotFoundException
import java.util.concurrent.ConcurrentHashMap

/**
 * Lets another app (a PDF reader, a DICOM viewer) open a vault file without a decrypted copy
 * ever being written to storage. The other app gets a seekable file descriptor; each read it
 * makes is decrypted on the fly from the encrypted file.
 *
 * Shared files are only registered in memory, so their links stop working once the app's
 * process ends, and the encrypted files themselves are wiped on the next launch.
 */
class SecureFileProvider : ContentProvider() {

    private data class Shared(val entryId: String, val displayName: String, val mimeType: String)

    override fun onCreate(): Boolean = true

    private fun lookup(uri: Uri): Shared {
        val token = uri.pathSegments.firstOrNull() ?: throw FileNotFoundException("Bad link")
        return shared[token] ?: throw FileNotFoundException("This link has expired")
    }

    override fun getType(uri: Uri): String? = runCatching { lookup(uri).mimeType }.getOrNull()

    override fun query(
        uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        val s = lookup(uri)
        val vault = FileVault(context!!)
        val size = vault.find(s.entryId)?.let { e -> vault.reader(e).use { it.plaintextLength } } ?: 0L
        val cols = projection?.filter { it == OpenableColumns.DISPLAY_NAME || it == OpenableColumns.SIZE }?.toTypedArray()
            ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return MatrixCursor(cols, 1).apply {
            addRow(cols.map { if (it == OpenableColumns.DISPLAY_NAME) s.displayName else size })
        }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw SecurityException("Read-only")
        val s = lookup(uri)
        val ctx = context!!
        val vault = FileVault(ctx)
        val entry = vault.find(s.entryId) ?: throw FileNotFoundException("File is gone")
        val reader = vault.reader(entry)
        val storage = ctx.getSystemService(StorageManager::class.java)
        return storage.openProxyFileDescriptor(
            ParcelFileDescriptor.MODE_READ_ONLY,
            object : ProxyFileDescriptorCallback() {
                override fun onGetSize(): Long = reader.plaintextLength
                override fun onRead(offset: Long, size: Int, data: ByteArray): Int = try {
                    reader.read(offset, size, data)
                } catch (e: Exception) {
                    throw ErrnoException("read", OsConstants.EIO)
                }
                override fun onRelease() = reader.close()
            },
            handler,
        )
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    companion object {
        private val shared = ConcurrentHashMap<String, Shared>()
        private val handler: Handler by lazy {
            Handler(HandlerThread("secure-file-reads").apply { start() }.looper)
        }

        fun authority(context: Context) = "${context.packageName}.secure"

        /** Registers a vault entry for sharing and returns a content:// link to grant to another app. */
        fun share(context: Context, entry: FileVault.Entry, displayName: String, mimeType: String): Uri {
            val token = java.util.UUID.randomUUID().toString()
            shared[token] = Shared(entry.id, displayName, mimeType)
            return Uri.Builder().scheme("content").authority(authority(context))
                .appendPath(token).appendPath(displayName).build()
        }

        fun revokeAll() = shared.clear()
    }
}
