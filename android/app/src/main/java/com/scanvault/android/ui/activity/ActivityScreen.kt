package com.scanvault.android.ui.activity

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Backup
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MedicalServices
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.scanvault.android.data.ActivityEntry
import com.scanvault.android.data.AppContainer
import com.scanvault.android.data.SessionState
import com.scanvault.android.ui.components.EmptyState
import com.scanvault.android.ui.components.Loadable
import com.scanvault.android.ui.components.LoadableContent
import com.scanvault.android.ui.components.formatBytes
import com.scanvault.android.ui.components.userMessage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.time.LocalDate
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

data class ActivityList(val entries: List<ActivityEntry>, val nextBefore: Long?, val loadingMore: Boolean = false)

class ActivityViewModel(
    private val container: AppContainer,
    private val patientId: String?,
    private val studyId: String?,
) : ViewModel() {
    private val _state = MutableStateFlow<Loadable<ActivityList>>(Loadable.Loading)
    val state = _state.asStateFlow()

    fun load() {
        if (_state.value !is Loadable.Loaded) _state.value = Loadable.Loading
        viewModelScope.launch {
            container.call { it.activity(patientId, studyId, limit = PAGE) }
                .onSuccess { _state.value = Loadable.Loaded(ActivityList(it.entries, it.nextBefore)) }
                .onFailure { _state.value = Loadable.Failed(it.userMessage()) }
        }
    }

    fun loadMore() {
        val cur = (_state.value as? Loadable.Loaded)?.value ?: return
        val before = cur.nextBefore ?: return
        if (cur.loadingMore) return
        _state.value = Loadable.Loaded(cur.copy(loadingMore = true))
        viewModelScope.launch {
            container.call { it.activity(patientId, studyId, before = before, limit = PAGE) }
                .onSuccess { page ->
                    val seen = cur.entries.mapTo(HashSet()) { it.seq }
                    _state.value = Loadable.Loaded(ActivityList(cur.entries + page.entries.filter { it.seq !in seen }, page.nextBefore))
                }
                .onFailure { _state.value = Loadable.Loaded(cur.copy(loadingMore = false)) }
        }
    }

    private companion object { const val PAGE = 50 }
}

/**
 * Recent activity from the server's activity log: sign-ins, uploads, edits, deletes, views,
 * downloads and backups, newest first. Optionally limited to one patient or one study.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ActivityScreen(
    container: AppContainer,
    patientId: String?,
    studyId: String?,
    title: String?,
    onBack: () -> Unit,
) {
    val vm: ActivityViewModel = viewModel(key = "activity-$patientId-$studyId") { ActivityViewModel(container, patientId, studyId) }
    val state by vm.state.collectAsStateWithLifecycle()
    val session by container.session.collectAsStateWithLifecycle()
    LaunchedEffect(session) { if (session == SessionState.Ready) vm.load() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(if (title.isNullOrBlank()) "Recent activity" else "Activity")
                        if (!title.isNullOrBlank()) {
                            Text(title, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                    }
                },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
                actions = { IconButton(onClick = vm::load) { Icon(Icons.Default.Refresh, "Refresh") } },
            )
        },
    ) { padding ->
        LoadableContent(state, onRetry = vm::load, modifier = Modifier.padding(padding)) { list ->
            if (list.entries.isEmpty()) {
                EmptyState("No activity yet.", Modifier.padding(padding))
            } else {
                val rows = remember(list.entries) { withDayHeaders(list.entries) }
                LazyColumn(Modifier.padding(padding), contentPadding = PaddingValues(bottom = 24.dp)) {
                    items(rows, key = { it.key }) { row ->
                        when (row) {
                            is Row.Day -> Text(
                                row.label,
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp),
                            )
                            is Row.Item -> {
                                ActivityRow(row.entry, showPatient = patientId == null && studyId == null)
                                HorizontalDivider()
                            }
                        }
                    }
                    if (list.nextBefore != null) {
                        item(key = "more") {
                            LaunchedEffect(list.nextBefore) { vm.loadMore() }
                            Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
                                OutlinedButton(onClick = vm::loadMore, enabled = !list.loadingMore) {
                                    Text(if (list.loadingMore) "Loading…" else "Load older activity")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

private sealed interface Row {
    val key: String
    data class Day(val label: String) : Row { override val key get() = "d:$label" }
    data class Item(val entry: ActivityEntry) : Row { override val key get() = "e:${entry.seq}" }
}

private fun withDayHeaders(entries: List<ActivityEntry>): List<Row> {
    val out = ArrayList<Row>(entries.size + 8)
    var last: String? = null
    for (e in entries) {
        val day = dayLabel(e.at)
        if (day != last) { out += Row.Day(day); last = day }
        out += Row.Item(e)
    }
    return out
}

private fun parse(at: String) = runCatching { OffsetDateTime.parse(at).atZoneSameInstant(ZoneId.systemDefault()) }.getOrNull()

internal fun dayLabel(at: String): String {
    val t = parse(at) ?: return ""
    val today = LocalDate.now()
    return when (t.toLocalDate()) {
        today -> "Today"
        today.minusDays(1) -> "Yesterday"
        else -> t.format(DateTimeFormatter.ofLocalizedDate(FormatStyle.FULL))
    }
}

private fun timeLabel(at: String): String =
    parse(at)?.format(DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT)).orEmpty()

private fun iconFor(category: String): ImageVector = when (category) {
    "auth", "sso" -> Icons.Default.Key
    "vault" -> Icons.Default.Lock
    "patient" -> Icons.Default.Person
    "study" -> Icons.Default.MedicalServices
    "file" -> Icons.Default.Description
    "backup" -> Icons.Default.Backup
    "activity" -> Icons.Default.Shield
    else -> Icons.Default.History
}

private val CLIENTS = mapOf("android" to "Android app", "web" to "Web", "api" to "API", "system" to "ScanVault")

/** "Jane Doe · MRI knee · report.pdf" style summary of what an entry was about. */
internal fun ActivityEntry.target(showPatient: Boolean): String {
    val bits = mutableListOf<String>()
    if (showPatient) patientName?.let { bits += it }
    studyTitle?.let { bits += it }
    val file = detail("filename")
    if (file != null) bits += file
    else if (action == "file.upload") {
        val n = detail("files")?.toIntOrNull()
        val bytes = detail("bytes")?.toLongOrNull()
        if (n != null) bits += "$n file${if (n == 1) "" else "s"}" + (bytes?.let { " · ${formatBytes(it)}" } ?: "")
    }
    detail("target_name")?.let { bits += it }
    detail("provider")?.let { bits += it }
    if (failed) detail("reason")?.let { bits += it }
    return bits.joinToString(" · ")
}

@Composable
private fun ActivityRow(e: ActivityEntry, showPatient: Boolean) {
    val who = listOfNotNull(
        e.username ?: "Unknown",
        timeLabel(e.at).ifBlank { null },
        e.client?.takeIf { it != "web" }?.let { CLIENTS[it] ?: it },
    ).joinToString(" · ")
    val what = e.target(showPatient)
    ListItem(
        leadingContent = {
            Icon(
                iconFor(e.category),
                contentDescription = null,
                tint = if (e.failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
            )
        },
        headlineContent = {
            Text(
                (e.label.ifBlank { e.action }) + if (e.failed) " (failed)" else "",
                color = if (e.failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            )
        },
        supportingContent = {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                if (what.isNotBlank()) Text(what, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text(who, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        },
    )
}
