package com.medvault.android.data

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
    /** Imaging studies, without the studies that only hold a lab report's PDF. */
    @SerialName("scan_count") val scanCount: Int? = null,
    @SerialName("lab_report_count") val labReportCount: Int = 0,
    @SerialName("lab_draft_count") val labDraftCount: Int = 0,
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

/** Another study of the same patient, scored for how well it compares with the one being viewed. */
@Serializable
data class SimilarStudy(
    val id: String,
    @SerialName("patient_id") val patientId: String,
    val title: String,
    val modality: String? = null,
    @SerialName("study_date") val studyDate: String? = null,
    val facility: String? = null,
    @SerialName("body_part") val bodyPart: String? = null,
    val similarity: Double = 0.0,
    /** Same kind of exam: the server's pick for a side-by-side comparison. */
    val suggested: Boolean = false,
    @SerialName("match_reasons") val matchReasons: List<String> = emptyList(),
    @SerialName("days_apart") val daysApart: Int? = null,
    /** "prior", "later" or "same day", relative to the study being viewed. */
    val relation: String? = null,
    @SerialName("thumbnail_ids") val thumbnailIds: List<String> = emptyList(),
    @SerialName("image_count") val imageCount: Int = 0,
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

/** One entry of the server's activity log (who did what, and when). */
@Serializable
data class ActivityEntry(
    val seq: Long,
    val at: String,
    val action: String,
    val label: String = "",
    val category: String = "",
    val outcome: String? = null,
    @SerialName("user_id") val userId: String? = null,
    val username: String? = null,
    @SerialName("patient_id") val patientId: String? = null,
    @SerialName("patient_name") val patientName: String? = null,
    @SerialName("study_id") val studyId: String? = null,
    @SerialName("study_title") val studyTitle: String? = null,
    val client: String? = null,
    val ip: String? = null,
    val details: JsonObject? = null,
) {
    val failed: Boolean get() = outcome != null && outcome != "ok"

    /** A string detail such as "filename", or null. */
    fun detail(key: String): String? =
        (details?.get(key) as? kotlinx.serialization.json.JsonPrimitive)?.takeUnless { it is kotlinx.serialization.json.JsonNull }?.content
}

@Serializable
data class ActivityPage(
    val entries: List<ActivityEntry> = emptyList(),
    @SerialName("next_before") val nextBefore: Long? = null,
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

// --- LabsVault -----------------------------------------------------------------------------

/** One analyte the server knows (its catalog), for matching a test while reviewing. */
@Serializable
data class LabCatalogEntry(val key: String, val name: String, val loinc: String? = null, val panel: String? = null)

@Serializable
data class LabInfo(
    val ocr: Boolean = false,
    val catalog: List<LabCatalogEntry> = emptyList(),
)

/** One saved value of one test. */
@Serializable
data class LabPoint(
    val id: String? = null,
    @SerialName("report_id") val reportId: String? = null,
    val date: String? = null,
    val value: String = "",
    @SerialName("value_num") val valueNum: Double? = null,
    val unit: String? = null,
    @SerialName("ref_low") val refLow: Double? = null,
    @SerialName("ref_high") val refHigh: Double? = null,
    @SerialName("ref_text") val refText: String? = null,
    val flag: String? = null,
    val source: String? = null,
    @SerialName("lab_name") val labName: String? = null,
)

@Serializable
data class LabAnalyte(
    val key: String,
    val name: String,
    val loinc: String? = null,
    val panel: String = "Other",
    val unit: String? = null,
    val count: Int = 0,
    val latest: LabPoint,
    /** [[date, number], ...] oldest first, for the sparkline. */
    val spark: List<kotlinx.serialization.json.JsonArray> = emptyList(),
) {
    val sparkValues: List<Double>
        get() = spark.mapNotNull { (it.getOrNull(1) as? kotlinx.serialization.json.JsonPrimitive)?.content?.toDoubleOrNull() }
}

@Serializable
data class LabSeries(
    val key: String,
    val name: String,
    val loinc: String? = null,
    val units: List<String> = emptyList(),
    val points: List<LabPoint> = emptyList(),
)

/** A result row of a report: parsed from the PDF (draft) or saved. Field names match the server. */
@Serializable
data class LabRow(
    val name: String = "",
    val value: String = "",
    val analyte: String? = null,
    val catalog: Boolean? = null,
    val panel: String? = null,
    val unit: String? = null,
    @SerialName("ref_low") val refLow: Double? = null,
    @SerialName("ref_high") val refHigh: Double? = null,
    @SerialName("ref_text") val refText: String? = null,
    val flag: String? = null,
    @SerialName("prev_value") val prevValue: String? = null,
    @SerialName("prev_date") val prevDate: String? = null,
    val confidence: String? = null,
    val source: String? = null,
    val include: Boolean = true,
)

@Serializable
data class LabReport(
    val id: String,
    @SerialName("patient_id") val patientId: String,
    val status: String = "draft",
    val lab: String? = null,
    @SerialName("lab_name") val labName: String? = null,
    val collected: String? = null,
    val reported: String? = null,
    @SerialName("ordering_provider") val orderingProvider: String? = null,
    @SerialName("file_id") val fileId: String? = null,
    val filename: String? = null,
    val method: String? = null,
    @SerialName("result_count") val resultCount: Int = 0,
    @SerialName("flagged_count") val flaggedCount: Int = 0,
    val rows: List<LabRow> = emptyList(),
    val warnings: List<String> = emptyList(),
    val duplicate: Boolean = false,
) {
    val isDraft: Boolean get() = status == "draft"
}

@Serializable
data class LabReportUpdate(
    val lab: String? = null,
    val collected: String? = null,
    val reported: String? = null,
    @SerialName("ordering_provider") val orderingProvider: String? = null,
    val rows: List<LabRow>? = null,
    val save: Boolean = false,
    @SerialName("import_previous") val importPrevious: Boolean = true,
)
