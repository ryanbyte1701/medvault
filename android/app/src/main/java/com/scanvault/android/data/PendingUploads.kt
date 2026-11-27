package com.scanvault.android.data

import android.content.Context
import com.scanvault.android.data.crypto.EncryptedPrefs
import com.scanvault.android.data.crypto.FileVault
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/** A camera photo that is stored encrypted on the phone because its upload hasn't succeeded yet. */
@Serializable
data class PendingUpload(
    val id: String,
    val studyId: String,
    val filename: String,
    val createdAtMillis: Long,
    val lastError: String? = null,
)

/**
 * Keeps camera photos safe until they upload: a failed upload never deletes the photo. Each
 * photo is encrypted in the vault's pending area, and this list (itself encrypted) remembers
 * which study it belongs to, so the study screen can offer Retry or Discard.
 */
class PendingUploads(context: Context, private val vault: FileVault) {
    private val prefs = EncryptedPrefs(context, "pending_uploads")
    private val json = Json { ignoreUnknownKeys = true }
    private val serializer = ListSerializer(PendingUpload.serializer())

    private val _items = MutableStateFlow(load())
    val items: StateFlow<List<PendingUpload>> = _items.asStateFlow()

    private fun load(): List<PendingUpload> =
        prefs.getString("items")?.let { runCatching { json.decodeFromString(serializer, it) }.getOrNull() }
            ?.filter { vault.find(it.id, FileVault.Area.PENDING) != null }
            ?: emptyList()

    @Synchronized
    private fun save(list: List<PendingUpload>) {
        prefs.putString("items", json.encodeToString(serializer, list))
        _items.value = list
    }

    @Synchronized
    fun add(item: PendingUpload) = save(_items.value.filter { it.id != item.id } + item)

    @Synchronized
    fun markFailed(id: String, error: String) =
        save(_items.value.map { if (it.id == id) it.copy(lastError = error) else it })

    @Synchronized
    fun remove(id: String) {
        vault.find(id, FileVault.Area.PENDING)?.let(vault::delete)
        save(_items.value.filter { it.id != id })
    }

    fun forStudy(studyId: String) = _items.value.filter { it.studyId == studyId }

    fun entry(item: PendingUpload): FileVault.Entry? = vault.find(item.id, FileVault.Area.PENDING)

    @Synchronized
    fun clear() {
        vault.clear(FileVault.Area.PENDING)
        save(emptyList())
    }
}
