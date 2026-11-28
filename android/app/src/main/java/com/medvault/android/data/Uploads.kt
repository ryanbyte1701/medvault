package com.medvault.android.data

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap

/** Builds an [UploadPart] from a content:// or file:// Uri without reading it into memory. */
fun ContentResolver.uploadPartFor(uri: Uri): UploadPart {
    // Only accept documents from other apps' providers: never file:// paths or this app's own
    // providers, which could be abused to upload the app's private files.
    require(uri.scheme == ContentResolver.SCHEME_CONTENT) { "Unsupported file location" }
    require(uri.authority?.startsWith(com.medvault.android.BuildConfig.APPLICATION_ID) != true) {
        "Unsupported file location"
    }
    var name: String? = null
    var size = -1L
    run {
        query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val si = c.getColumnIndex(OpenableColumns.SIZE)
                if (ni >= 0) name = c.getString(ni)
                if (si >= 0 && !c.isNull(si)) size = c.getLong(si)
            }
        }
    }
    val filename = (name ?: uri.lastPathSegment ?: "upload").substringAfterLast('/').ifBlank { "upload" }
    val type = getType(uri)?.takeIf { it != "application/octet-stream" } ?: guessMimeType(filename)
    return UploadPart(filename, type, size) {
        openInputStream(uri) ?: throw java.io.FileNotFoundException("Can't open $filename")
    }
}

fun guessMimeType(filename: String): String {
    val ext = filename.substringAfterLast('.', "").lowercase()
    return when (ext) {
        "dcm", "dicom" -> "application/dicom"
        "" -> "application/octet-stream"
        else -> MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
    }
}

/** Picks the server-side "kind" for an upload from its type and name. */
fun kindFor(part: UploadPart): String = kindFor(part.filename, part.contentType)

fun kindFor(filename: String, contentType: String): String {
    val lower = filename.lowercase()
    return when {
        contentType == "application/dicom" || lower.endsWith(".dcm") -> VaultFile.KIND_DICOM
        contentType.startsWith("image/") -> VaultFile.KIND_IMAGE
        contentType == "application/pdf" || contentType.startsWith("text/") ||
            contentType.contains("word") || lower.endsWith(".pdf") -> VaultFile.KIND_REPORT
        else -> VaultFile.KIND_OTHER
    }
}
