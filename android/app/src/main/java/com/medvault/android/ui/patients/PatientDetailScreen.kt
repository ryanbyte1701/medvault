package com.medvault.android.ui.patients

import com.medvault.android.ui.components.GuardDialogTouches
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FolderZip
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.MedicalServices
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Science
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.medvault.android.data.AppContainer
import com.medvault.android.data.Patient
import com.medvault.android.data.SessionState
import com.medvault.android.data.Study
import com.medvault.android.data.StudyInput
import com.medvault.android.data.uploadPartFor
import com.medvault.android.ui.components.EmptyState
import com.medvault.android.ui.components.Loadable
import com.medvault.android.ui.components.LoadableContent
import com.medvault.android.ui.components.userMessage
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import com.medvault.android.ui.labs.LabsOverview
import com.medvault.android.ui.labs.LabsTabContent
import com.medvault.android.ui.labs.LabsViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class PatientDetail(val patient: Patient, val studies: List<Study>)

class PatientDetailViewModel(private val container: AppContainer, private val patientId: String) : ViewModel() {
    private val _state = MutableStateFlow<Loadable<PatientDetail>>(Loadable.Loading)
    val state = _state.asStateFlow()
    private val _importing = MutableStateFlow(false)
    val importing = _importing.asStateFlow()

    fun load() {
        if (_state.value !is Loadable.Loaded) _state.value = Loadable.Loading
        viewModelScope.launch {
            container.call { api ->
                PatientDetail(api.patient(patientId), api.studies(patientId).sortedByDescending { it.studyDate ?: it.createdAt })
            }.onSuccess { _state.value = Loadable.Loaded(it) }
                .onFailure { _state.value = Loadable.Failed(it.userMessage()) }
        }
    }

    suspend fun createStudy(input: StudyInput): Result<Study> =
        container.call { it.createStudy(patientId, input) }.onSuccess { load() }

    suspend fun delete(): Result<Unit> = container.call { it.deletePatient(patientId) }

    /** Sends DICOM files or a zipped imaging-CD export; the server groups them into studies. */
    val messages = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.BUFFERED)

    /**
     * Imports in the ViewModel's scope so a rotation doesn't cancel it, and always clears the
     * progress bar when done.
     */
    fun importFiles(parts: List<com.medvault.android.data.UploadPart>) {
        if (_importing.value) return
        _importing.value = true
        viewModelScope.launch {
            val result = try {
                container.call { it.importToPatient(patientId, parts) }
            } finally {
                _importing.value = false
            }
            load()
            result.map { r ->
                buildString {
                    append("Imported ${r.files.size} file(s) into ${r.studies.size} study(ies)")
                    if (r.skipped.isNotEmpty()) append(", skipped ${r.skipped.size}")
                }
            }.onSuccess { messages.trySend(it) }
                .onFailure { messages.trySend("Import failed: ${it.userMessage()}") }
        }
    }
}

/** The two halves of a patient record. */
enum class PatientTab { Scans, Labs }

/** Lab report PDFs are filed in a study of this modality; they are reached from the Labs tab. */
private const val LAB_MODALITY = "LAB"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatientDetailScreen(
    container: AppContainer,
    patientId: String,
    onBack: () -> Unit,
    onOpenStudy: (String) -> Unit,
    onOpenActivity: (patientName: String) -> Unit = {},
    initialTab: PatientTab = PatientTab.Scans,
    onOpenLabReport: (String) -> Unit = {},
    onOpenLabTrend: (String) -> Unit = {},
) {
    val vm: PatientDetailViewModel = viewModel(key = "patient-$patientId") { PatientDetailViewModel(container, patientId) }
    val labsVm: LabsViewModel = viewModel(key = "labs-$patientId") { LabsViewModel(container, patientId) }
    val state by vm.state.collectAsStateWithLifecycle()
    val importing by vm.importing.collectAsStateWithLifecycle()
    val labs by labsVm.state.collectAsStateWithLifecycle()
    val labUploading by labsVm.uploading.collectAsStateWithLifecycle()
    val session by container.session.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()
    val resolver = LocalContext.current.contentResolver
    var tab by rememberSaveable { mutableStateOf(initialTab) }
    var showAdd by rememberSaveable { mutableStateOf(false) }
    var menu by remember { mutableStateOf(false) }
    var confirmDelete by rememberSaveable { mutableStateOf(false) }

    // Both tabs load up front, so their counts are right and switching is instant.
    LaunchedEffect(session) {
        if (session == SessionState.Ready) {
            vm.load()
            labsVm.load()
        }
    }

    val importPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        val parts = uris.mapNotNull { runCatching { resolver.uploadPartFor(it) }.getOrNull() }
        if (parts.isNotEmpty()) vm.importFiles(parts)
        else scope.launch { snackbar.showSnackbar("Those files couldn't be read") }
    }
    val labPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        val part = runCatching { resolver.uploadPartFor(uri) }.getOrNull()
        if (part != null) labsVm.upload(part) else scope.launch { snackbar.showSnackbar("That file couldn't be read") }
    }
    LaunchedEffect(vm) { for (m in vm.messages) snackbar.showSnackbar(m) }
    LaunchedEffect(labsVm) { for (m in labsVm.messages) snackbar.showSnackbar(m) }
    LaunchedEffect(labsVm) { for (id in labsVm.openReview) onOpenLabReport(id) }

    val patientName = (state as? Loadable.Loaded<PatientDetail>)?.value?.patient?.name

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(patientName ?: "Patient") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
                actions = {
                    if (tab == PatientTab.Labs) {
                        IconButton(onClick = {
                            scope.launch {
                                labsVm.newManualReport().onSuccess { onOpenLabReport(it.id) }
                                    .onFailure { snackbar.showSnackbar(it.userMessage()) }
                            }
                        }) { Icon(Icons.Default.Edit, "Enter lab results by hand") }
                    }
                    IconButton(onClick = { menu = true }) { Icon(Icons.Default.MoreVert, "More") }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        if (tab == PatientTab.Scans) DropdownMenuItem(
                            text = { Text("Import DICOM / CD (.zip)") },
                            leadingIcon = { Icon(Icons.Default.FolderZip, null) },
                            onClick = {
                                menu = false
                                container.appLock.expectExternalTrip()
                                importPicker.launch(arrayOf("application/zip", "application/dicom", "application/octet-stream", "*/*"))
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("Activity") },
                            leadingIcon = { Icon(Icons.Default.History, null) },
                            onClick = {
                                menu = false
                                onOpenActivity(patientName.orEmpty())
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("Delete patient") },
                            leadingIcon = { Icon(Icons.Default.Delete, null) },
                            onClick = { menu = false; confirmDelete = true },
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            when (tab) {
                PatientTab.Scans -> ExtendedFloatingActionButton(
                    onClick = { showAdd = true },
                    icon = { Icon(Icons.Default.Add, null) },
                    text = { Text("Study") },
                )
                PatientTab.Labs -> ExtendedFloatingActionButton(
                    onClick = {
                        if (!labUploading) {
                            container.appLock.expectExternalTrip()
                            labPicker.launch(arrayOf("application/pdf", "image/*"))
                        }
                    },
                    icon = { Icon(Icons.Default.UploadFile, null) },
                    text = { Text("Lab report") },
                )
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        LoadableContent(state, onRetry = vm::load, modifier = Modifier.padding(padding)) { detail ->
            val scans = detail.studies.filter { it.modality != LAB_MODALITY }
            val labCount = (labs as? Loadable.Loaded<LabsOverview>)?.value?.reports?.count { !it.isDraft }
                ?: detail.patient.labReportCount
            Column(Modifier.padding(padding)) {
                if (importing) LinearProgressIndicator(Modifier.fillMaxWidth())
                PatientHeader(detail.patient)
                PrimaryTabRow(selectedTabIndex = tab.ordinal) {
                    Tab(
                        selected = tab == PatientTab.Scans,
                        onClick = { tab = PatientTab.Scans },
                        icon = { Icon(Icons.Default.MedicalServices, null) },
                        text = { Text("Scans (${scans.size})") },
                    )
                    Tab(
                        selected = tab == PatientTab.Labs,
                        onClick = { tab = PatientTab.Labs },
                        icon = { Icon(Icons.Default.Science, null) },
                        text = { Text("Labs ($labCount)") },
                    )
                }
                when (tab) {
                    PatientTab.Scans -> ScansTab(scans, onOpenStudy)
                    PatientTab.Labs -> LoadableContent(labs, onRetry = labsVm::load) { o ->
                        LabsTabContent(o, labUploading, onOpenLabReport, onOpenLabTrend)
                    }
                }
            }
        }
    }

    if (showAdd) {
        AddStudyDialog(onDismiss = { showAdd = false }, onSave = { vm.createStudy(it).map { } })
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { GuardDialogTouches(); Text("Delete patient?") },
            text = { Text("This removes the patient and all of their scans, lab results and files from the vault. Existing backups are not touched.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    scope.launch {
                        vm.delete().onSuccess { onBack() }
                            .onFailure { snackbar.showSnackbar("Delete failed: ${it.userMessage()}") }
                    }
                }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun ScansTab(studies: List<Study>, onOpenStudy: (String) -> Unit) {
    if (studies.isEmpty()) {
        EmptyState("No scans yet. Add a study for a scan visit, or import a DICOM CD export from the menu.")
        return
    }
    LazyColumn(contentPadding = PaddingValues(bottom = 88.dp)) {
        items(studies, key = { it.id }) { s ->
            ListItem(
                leadingContent = { Icon(Icons.Default.MedicalServices, null) },
                headlineContent = { Text(s.title) },
                overlineContent = {
                    Text(listOfNotNull(s.modality, s.studyDate).joinToString(" · "))
                },
                supportingContent = {
                    Text(listOfNotNull(s.facility, "${s.fileCount} file(s)").joinToString(" · "))
                },
                modifier = Modifier.clickable { onOpenStudy(s.id) },
            )
            HorizontalDivider()
        }
    }
}

@Composable
private fun PatientHeader(p: Patient) {
    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        val facts = listOfNotNull(
            p.dateOfBirth?.let { "DOB $it" },
            p.sex,
            p.mrn?.let { "MRN $it" },
        )
        if (facts.isNotEmpty()) Text(facts.joinToString(" · "), style = MaterialTheme.typography.bodyLarge)
        p.notes?.let {
            Text(it, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun AddStudyDialog(onDismiss: () -> Unit, onSave: suspend (StudyInput) -> Result<Unit>) {
    var title by rememberSaveable { mutableStateOf("") }
    var modality by rememberSaveable { mutableStateOf("") }
    var date by rememberSaveable { mutableStateOf("") }
    var facility by rememberSaveable { mutableStateOf("") }
    var description by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val dateValid = date.isBlank() || Regex("""\d{4}-\d{2}-\d{2}""").matches(date.trim())

    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { GuardDialogTouches(); Text("New study") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(title, { title = it }, label = { Text("Title, e.g. MRI left knee") }, singleLine = true)
                OutlinedTextField(modality, { modality = it }, label = { Text("Modality (MR, CT, XR, US…)") }, singleLine = true)
                OutlinedTextField(date, { date = it }, label = { Text("Study date (YYYY-MM-DD)") },
                    singleLine = true, isError = !dateValid)
                OutlinedTextField(facility, { facility = it }, label = { Text("Imaging center") }, singleLine = true)
                OutlinedTextField(description, { description = it }, label = { Text("Notes") }, minLines = 2)
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !busy && title.isNotBlank() && dateValid,
                onClick = {
                    busy = true; error = null
                    scope.launch {
                        onSave(StudyInput(
                            title = title.trim(),
                            modality = modality.trim().ifBlank { null },
                            studyDate = date.trim().ifBlank { null },
                            facility = facility.trim().ifBlank { null },
                            description = description.trim().ifBlank { null },
                        )).onSuccess { onDismiss() }.onFailure { error = it.userMessage() }
                        busy = false
                    }
                },
            ) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss, enabled = !busy) { Text("Cancel") } },
    )
}
