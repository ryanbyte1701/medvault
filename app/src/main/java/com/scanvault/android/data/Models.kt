package com.scanvault.android.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
data class LoginRequest(
    val username: String,
    val password: String,
    /** Proof this app signed in to the account before; lets the server skip its account lockout. */
    val device: String? = null,
)

@Serializable
data class LoginResponse(
    val token: String,
    @SerialName("expires_at") val expiresAt: String? = null,
    /** Whether the vault is unlocked; SSO never unlocks it, so false means ask for the passphrase. */
    val unlocked: Boolean? = null,
    /** Device token to store and send back on the next password sign-in (non-browser clients). */
    val device: String? = null,
)

/** An identity provider the server offers for single sign-on. */
@Serializable
data class SsoProvider(val id: String, val name: String, val preset: String? = null)

@Serializable
data class SsoExchangeRequest(
    val ticket: String,
    @SerialName("code_verifier") val codeVerifier: String,
)

@Serializable
data class ServerStatus(
    @SerialName("setup_complete") val setupComplete: Boolean = true,
    val unlocked: Boolean = true,
    val authenticated: Boolean = false,
    val username: String? = null,
    @SerialName("vault_id") val vaultId: String? = null,
    val fingerprint: String? = null,
    val version: String? = null,
    /** False when the server only allows SSO, so the password form is hidden. */
    @SerialName("local_login") val localLogin: Boolean = true,
    val sso: List<SsoProvider> = emptyList(),
)

@Serializable
data class UnlockRequest(
    val passphrase: String? = null,
    @SerialName("recovery_key") val recoveryKey: String? = null,
)

@Serializable
data class Patient(
    val id: String,
    val name: String,
    @SerialName("date_of_birth") val dateOfBirth: String? = null,
    val sex: String? = null,
    val mrn: String? = null,
    val notes: String? = null,
    @SerialName("study_count") val studyCount: Int = 0,
)

@Serializable
data class PatientInput(
    val name: String,
    @SerialName("date_of_birth") val dateOfBirth: String? = null,
    val sex: String? = null,
    val mrn: String? = null,
    val notes: String? = null,
)

@Serializable
data class Study(
    val id: String,
    @SerialName("patient_id") val patientId: String,
    val title: String,
    val modality: String? = null,
    @SerialName("study_date") val studyDate: String? = null,
    val facility: String? = null,
    val description: String? = null,
    @SerialName("file_count") val fileCount: Int = 0,
    @SerialName("created_at") val createdAt: String? = null,
)

@Serializable
data class StudyInput(
    val title: String,
    val modality: String? = null,
    @SerialName("study_date") val studyDate: String? = null,
    val facility: String? = null,
    val description: String? = null,
)

@Serializable
data class VaultFile(
    val id: String,
    @SerialName("study_id") val studyId: String,
    /** The server can return null for a blank name; default it so one bad file can't break a study. */
    val filename: String = "file",
    @SerialName("content_type") val contentType: String = "application/octet-stream",
    @SerialName("size_bytes") val sizeBytes: Long = 0,
    val kind: String = KIND_OTHER,
    @SerialName("uploaded_at") val uploadedAt: String? = null,
    @SerialName("has_thumbnail") val hasThumbnail: Boolean = false,
    val dicom: JsonObject? = null,
    /** True when the server already had these exact bytes in the study and skipped storing a copy. */
    val duplicate: Boolean = false,
) {
    val isImage: Boolean get() = kind == KIND_IMAGE || contentType.startsWith("image/")

    companion object {
        const val KIND_IMAGE = "image"
        const val KIND_REPORT = "report"
        const val KIND_DICOM = "dicom"
        const val KIND_OTHER = "other"
    }
}

@Serializable
data class ImportResult(
    val studies: List<Study> = emptyList(),
    val files: List<VaultFile> = emptyList(),
    val skipped: List<kotlinx.serialization.json.JsonElement> = emptyList(),
)

@Serializable
data class ErrorBody(val error: String? = null, val code: String? = null)

/** A server-rendered DICOM frame plus the window/level and value range the server used. */
class RenderedImage(
    val bytes: ByteArray,
    val center: Double,
    val width: Double,
    val defaultCenter: Double?,
    val defaultWidth: Double?,
    val min: Double?,
    val max: Double?,
    val frames: Int,
    val frame: Int,
    val rgb: Boolean,
    val modality: String?,
)

// --- Optional AI explanations (configured on the server; the API key never reaches the phone) ---

@Serializable
data class AiSettings(
    val enabled: Boolean = false,
    val provider: String = "anthropic",
    val model: String = "",
    /** Host the requests go to, for example api.anthropic.com or 192.168.1.20:11434. */
    val endpoint: String = "",
    @SerialName("key_set") val keySet: Boolean = false,
    @SerialName("default_language") val defaultLanguage: String = "English",
    val providers: Map<String, String> = emptyMap(),
    @SerialName("max_images") val maxImages: Int = 6,
    val disclaimer: String = "",
) {
    val providerName: String get() = providers[provider] ?: provider
}

@Serializable
data class AiPrepareRequest(
    @SerialName("study_id") val studyId: String,
    @SerialName("file_ids") val fileIds: List<String>,
    val task: String,
    val language: String,
    // No defaults: the app's Json doesn't encode default values, and these must always be sent.
    @SerialName("remove_identifiers") val removeIdentifiers: Boolean,
    val question: String,
)

@Serializable
data class AiPreviewImage(
    val label: String,
    val width: Int = 0,
    val height: Int = 0,
    /** data:image/jpeg;base64,... : exactly the bytes that will be sent. */
    @SerialName("data_url") val dataUrl: String,
)

@Serializable
data class AiPreviewPdf(val label: String, @SerialName("size_bytes") val sizeBytes: Long = 0)

/** What the server will send, for the user to review. Nothing has been sent yet. */
@Serializable
data class AiPreview(
    val token: String,
    @SerialName("expires_in") val expiresIn: Int = 900,
    val provider: String = "",
    val model: String = "",
    val endpoint: String = "",
    val task: String = "explain",
    val language: String = "English",
    @SerialName("remove_identifiers") val removeIdentifiers: Boolean = true,
    val removed: Map<String, Int> = emptyMap(),
    val warnings: List<String> = emptyList(),
    val context: String = "",
    val text: String = "",
    val question: String = "",
    val images: List<AiPreviewImage> = emptyList(),
    val pdfs: List<AiPreviewPdf> = emptyList(),
    val instructions: String = "",
    val disclaimer: String = "",
)

@Serializable
data class AiSendRequest(
    val token: String,
    /** The reviewed (possibly edited) report text; null keeps the server's version. */
    val text: String?,
    /** The user ticked "send this"; the server refuses without it. No default, so it's always encoded. */
    val confirm: Boolean,
)

@Serializable
data class AiResult(
    val text: String,
    val model: String = "",
    val task: String = "explain",
    val language: String = "English",
    val disclaimer: String = "",
    val truncated: Boolean = false,
)
