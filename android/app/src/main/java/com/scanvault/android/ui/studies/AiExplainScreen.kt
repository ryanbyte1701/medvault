package com.scanvault.android.ui.studies

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.graphics.BitmapFactory
import android.os.Build
import android.os.PersistableBundle
import android.util.Base64
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.scanvault.android.data.AiPrepareRequest
import com.scanvault.android.data.AiPreview
import com.scanvault.android.data.AiResult
import com.scanvault.android.data.AiSendRequest
import com.scanvault.android.data.AiSettings
import com.scanvault.android.data.ApiException
import com.scanvault.android.data.AppContainer
import com.scanvault.android.data.SessionState
import com.scanvault.android.data.VaultFile
import com.scanvault.android.ui.components.ErrorState
import com.scanvault.android.ui.components.userMessage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Plain-language explanation or translation of a study's report and images, through the AI
 * provider configured on the server. Two steps: the server prepares the exact payload (with
 * names, IDs and dates removed by default) and the user reviews it; only then is it sent.
 * The phone never holds the provider's API key.
 */
class AiViewModel(private val container: AppContainer, private val studyId: String) : ViewModel() {
    sealed interface Step {
        data object Loading : Step
        data class Failed(val message: String) : Step
        data class Choose(val settings: AiSettings, val files: List<VaultFile>) : Step
        data class Review(val settings: AiSettings, val files: List<VaultFile>, val preview: AiPreview) : Step
        data class Done(val result: AiResult) : Step
    }

    private val _step = MutableStateFlow<Step>(Step.Loading)
    val step = _step.asStateFlow()
    private val _busy = MutableStateFlow(false)
    val busy = _busy.asStateFlow()
    private val _error = MutableStateFlow<String?>(null)
    val error = _error.asStateFlow()

    // The choices on the first screen live here so they survive rotation and Back from the review.
    var task by mutableStateOf("explain")
    var language by mutableStateOf("")
    var removeIdentifiers by mutableStateOf(true)
    var question by mutableStateOf("")
    var picked by mutableStateOf<Set<String>>(emptySet())

    fun load() {
        _step.value = Step.Loading
        viewModelScope.launch {
            container.call { api -> api.aiSettings() to api.files(studyId) }
                .onSuccess { (settings, all) ->
                    if (!settings.enabled) {
                        _step.value = Step.Failed("AI explanations are turned off. An administrator can turn them on in the ScanVault web app's Settings.")
                        return@onSuccess
                    }
                    val files = all.filter { usable(it) }
                    if (language.isBlank()) language = settings.defaultLanguage
                    if (picked.isEmpty()) {
                        picked = files.filter { it.kind == VaultFile.KIND_REPORT }.map { it.id }.toSet()
                            .ifEmpty { files.take(1).map { it.id }.toSet() }
                    }
                    _step.value = Step.Choose(settings, files)
                }
                .onFailure {
                    _step.value = Step.Failed(
                        if (it is ApiException && it.status == 404) "This server doesn't offer AI explanations."
                        else it.userMessage(),
                    )
                }
        }
    }

    fun prepare(settings: AiSettings, files: List<VaultFile>) {
        if (_busy.value) return
        if (picked.isEmpty()) { _error.value = "Choose at least one report or image."; return }
        _busy.value = true
        _error.value = null
        viewModelScope.launch {
            val req = AiPrepareRequest(
                studyId = studyId,
                fileIds = files.map { it.id }.filter { it in picked },
                task = task,
                language = language.trim().ifBlank { "English" },
                removeIdentifiers = removeIdentifiers,
                question = if (task == "explain") question.trim() else "",
            )
            container.call { it.aiPrepare(req) }
                .onSuccess { _step.value = Step.Review(settings, files, it) }
                .onFailure { _error.value = it.userMessage() }
            _busy.value = false
        }
    }

    fun send(preview: AiPreview, text: String?) {
        if (_busy.value) return
        _busy.value = true
        _error.value = null
        viewModelScope.launch {
            container.call { it.aiSend(AiSendRequest(token = preview.token, text = text, confirm = true)) }
                .onSuccess { _step.value = Step.Done(it) }
                .onFailure { e ->
                    _error.value = e.userMessage()
                    // An expired or already-used preview can't be sent; go back so it can be prepared again.
                    if (e is ApiException && e.code == "ai_expired") backToChoose()
                }
            _busy.value = false
        }
    }

    fun backToChoose() {
        val s = _step.value
        if (s is Step.Review) _step.value = Step.Choose(s.settings, s.files)
    }

    companion object {
        fun usable(f: VaultFile): Boolean =
            f.kind == VaultFile.KIND_REPORT || f.kind == VaultFile.KIND_DICOM || f.contentType.startsWith("image/")
    }
}

private val REMOVED_LABELS = mapOf(
    "name" to "name", "dob" to "birth date", "id" to "ID number", "clinician" to "clinician name",
    "facility" to "facility name", "date" to "date", "phone" to "phone number", "email" to "e-mail address",
    "url" to "link", "address" to "address", "labeled field" to "labeled field",
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AiExplainScreen(container: AppContainer, studyId: String, onBack: () -> Unit) {
    val vm: AiViewModel = viewModel(key = "ai-$studyId") { AiViewModel(container, studyId) }
    val step by vm.step.collectAsStateWithLifecycle()
    val busy by vm.busy.collectAsStateWithLifecycle()
    val error by vm.error.collectAsStateWithLifecycle()
    val session by container.session.collectAsStateWithLifecycle()

    LaunchedEffect(session) { if (session == SessionState.Ready && vm.step.value is AiViewModel.Step.Loading) vm.load() }
    BackHandler(enabled = step is AiViewModel.Step.Review && !busy) { vm.backToChoose() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Explain or translate") },
                navigationIcon = {
                    IconButton(onClick = { if (step is AiViewModel.Step.Review) vm.backToChoose() else onBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val s = step) {
                AiViewModel.Step.Loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
                is AiViewModel.Step.Failed -> ErrorState(s.message, onRetry = vm::load)
                is AiViewModel.Step.Choose -> ChooseStep(vm, s.settings, s.files, busy, error)
                is AiViewModel.Step.Review -> ReviewStep(vm, s.preview, busy, error)
                is AiViewModel.Step.Done -> ResultStep(s.result, onDone = onBack)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChooseStep(vm: AiViewModel, settings: AiSettings, files: List<VaultFile>, busy: Boolean, error: String?) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Notice(Icons.Default.Info, "${settings.disclaimer} Nothing is sent until you review it on the next screen.")
        val tasks = listOf("explain" to "Explain", "translate" to "Translate")
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            tasks.forEachIndexed { i, (key, label) ->
                SegmentedButton(
                    selected = vm.task == key,
                    onClick = { vm.task = key },
                    shape = SegmentedButtonDefaults.itemShape(i, tasks.size),
                ) { Text(label) }
            }
        }
        OutlinedTextField(
            value = vm.language,
            onValueChange = { vm.language = it.take(40) },
            label = { Text(if (vm.task == "explain") "Answer in" else "Translate into") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Text("What to include (up to ${settings.maxImages} images)", style = MaterialTheme.typography.titleSmall)
        if (files.isEmpty()) {
            Text("This study has no reports or images yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        files.forEach { f ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = f.id in vm.picked,
                    onCheckedChange = { on -> vm.picked = if (on) vm.picked + f.id else vm.picked - f.id },
                )
                Text(fileLabel(f), maxLines = 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
            }
        }
        ListItem(
            headlineContent = { Text("Remove names, ID numbers and dates first") },
            supportingContent = {
                Text("Recommended. Best effort: you'll see the exact text before it's sent. Words printed inside images can't be removed.")
            },
            trailingContent = { Switch(checked = vm.removeIdentifiers, onCheckedChange = { vm.removeIdentifiers = it }) },
        )
        if (vm.task == "explain") {
            OutlinedTextField(
                value = vm.question,
                onValueChange = { vm.question = it.take(2000) },
                label = { Text("Your question (optional)") },
                minLines = 2,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(
            onClick = { vm.prepare(settings, files) },
            enabled = !busy && files.isNotEmpty(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Text("Review what will be sent")
        }
    }
}

@Composable
private fun ReviewStep(vm: AiViewModel, preview: AiPreview, busy: Boolean, error: String?) {
    var text by rememberSaveable(preview.token) { mutableStateOf(preview.text) }
    var agreed by rememberSaveable(preview.token) { mutableStateOf(false) }
    var showInstructions by rememberSaveable { mutableStateOf(false) }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Notice(
            Icons.Default.Warning,
            "This will be sent to ${preview.provider} at ${preview.endpoint} (model ${preview.model}). " +
                "Only what's shown below leaves ScanVault. Check it for anything you don't want to share.",
            warn = true,
        )
        if (preview.removeIdentifiers) {
            val removed = preview.removed.entries.joinToString(", ") { (k, n) ->
                "$n ${REMOVED_LABELS[k] ?: k}${if (n == 1) "" else "s"}"
            }
            Text(
                if (removed.isNotEmpty()) "Removed: $removed. Placeholders like [NAME] show where."
                else "No names, IDs or dates were found to remove.",
                style = MaterialTheme.typography.bodySmall,
            )
        } else {
            Text("Identifiers were not removed.", fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodySmall)
        }
        preview.warnings.forEach { Notice(Icons.Default.Info, it) }
        if (preview.context.isNotBlank()) Text("Study: ${preview.context}", style = MaterialTheme.typography.bodySmall)
        if (preview.text.isNotEmpty()) {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text("Report text (you can edit it)") },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                minLines = 6,
                maxLines = 16,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        if (preview.question.isNotBlank()) Text("Your question: ${preview.question}", style = MaterialTheme.typography.bodySmall)
        if (preview.images.isNotEmpty()) {
            Text("Images (${preview.images.size})", style = MaterialTheme.typography.titleSmall)
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(preview.images, key = { it.label }) { im ->
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        DataUrlImage(im.dataUrl, im.label)
                        Text(im.label, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
        if (preview.pdfs.isNotEmpty()) {
            Text("Whole PDFs: " + preview.pdfs.joinToString(", ") { it.label }, style = MaterialTheme.typography.bodySmall)
        }
        TextButton(onClick = { showInstructions = !showInstructions }) {
            Text(if (showInstructions) "Hide instructions sent to the model" else "Show instructions sent to the model")
        }
        if (showInstructions) {
            Text(preview.instructions, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = agreed, onCheckedChange = { agreed = it })
            Text("Send this to ${preview.endpoint}. I understand the answer is not medical advice.")
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = vm::backToChoose, enabled = !busy, modifier = Modifier.weight(1f)) { Text("Back") }
            Button(
                onClick = { vm.send(preview, if (preview.text.isNotEmpty()) text else null) },
                enabled = agreed && !busy,
                modifier = Modifier.weight(1f),
            ) {
                if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Text("Send")
            }
        }
    }
}

@Composable
private fun ResultStep(result: AiResult, onDone: () -> Unit) {
    val context = LocalContext.current
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Notice(Icons.Default.Warning, result.disclaimer, warn = true)
        Card(Modifier.fillMaxWidth()) {
            // Plain text only: the answer is never interpreted as markup or links.
            SelectionContainer { Text(result.text, modifier = Modifier.padding(16.dp)) }
        }
        if (result.truncated) {
            Text("The answer was cut off because it reached the length limit.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(
            "Answered by ${result.model}. Not saved in ScanVault; the request is in the server's AI activity log.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(onClick = { copySensitive(context, "${result.text}\n\n---\n${result.disclaimer}") }, modifier = Modifier.weight(1f)) {
                Text("Copy")
            }
            Button(onClick = onDone, modifier = Modifier.weight(1f)) { Text("Done") }
        }
    }
}

@Composable
private fun Notice(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String, warn: Boolean = false) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = if (warn) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.secondaryContainer,
        ),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(12.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
            Text(text, style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** Shows the exact JPEG the server will send (a data: URL), decoded on the phone. */
@Composable
private fun DataUrlImage(dataUrl: String, label: String) {
    val bitmap = remember(dataUrl) {
        runCatching {
            val bytes = Base64.decode(dataUrl.substringAfter(","), Base64.DEFAULT)
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap()
        }.getOrNull()
    }
    Box(Modifier.size(140.dp), contentAlignment = Alignment.Center) {
        if (bitmap != null) {
            Image(bitmap, contentDescription = label, contentScale = ContentScale.Fit, modifier = Modifier.fillMaxSize())
        } else {
            Text("Can't show preview", style = MaterialTheme.typography.labelSmall)
        }
    }
}

private fun fileLabel(f: VaultFile): String {
    val d = f.dicom
    fun tag(key: String) = (d?.get(key) as? kotlinx.serialization.json.JsonPrimitive)?.content?.takeIf { it.isNotBlank() }
    return when (f.kind) {
        VaultFile.KIND_REPORT -> "Report: ${f.filename}"
        VaultFile.KIND_DICOM -> "Image: " + (tag("series_description") ?: "DICOM") + (tag("instance_number")?.let { " #$it" } ?: "")
        else -> "Photo: ${f.filename}"
    }
}

/** Copies text, flagged so Android 13+ doesn't show it in the clipboard preview. */
private fun copySensitive(context: android.content.Context, text: String) {
    val cm = context.getSystemService(ClipboardManager::class.java) ?: return
    val clip = ClipData.newPlainText("ScanVault", text)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
    } else {
        clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
    }
    cm.setPrimaryClip(clip)
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
        android.widget.Toast.makeText(context, "Copied", android.widget.Toast.LENGTH_SHORT).show()
    }
}
