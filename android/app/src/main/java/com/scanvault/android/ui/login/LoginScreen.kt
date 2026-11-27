package com.scanvault.android.ui.login

import com.scanvault.android.ui.components.GuardDialogTouches
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Login
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Switch
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.scanvault.android.data.ApiClient
import com.scanvault.android.data.AppContainer
import com.scanvault.android.data.net.HttpClients
import com.scanvault.android.data.net.UntrustedCertificateException
import com.scanvault.android.data.SsoProvider
import com.scanvault.android.ui.components.userMessage
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun LoginScreen(container: AppContainer, onOpenSettings: () -> Unit, onSignedIn: () -> Unit) {
    var server by rememberSaveable { mutableStateOf(container.store.serverUrl.orEmpty()) }
    var username by rememberSaveable { mutableStateOf(container.store.username.orEmpty()) }
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    val insecure = server.trim().startsWith("http://", ignoreCase = true)
    val serverHost = remember(server) { runCatching { ApiClient.normalizeBaseUrl(server).host }.getOrNull() }
    var allowLanHttp by remember(serverHost) {
        mutableStateOf(serverHost != null && container.store.allowsLanHttp(serverHost))
    }
    // The status probe hit a certificate Android doesn't trust; offer to review it.
    var probeCert by remember { mutableStateOf<UntrustedCertificateException?>(null) }
    // A self-signed certificate the user is being asked to approve (trust on first use).
    var untrusted by remember { mutableStateOf<UntrustedCertificateException?>(null) }
    val context = LocalContext.current
    val ssoError by container.ssoError.collectAsStateWithLifecycle()

    // Ask the server which sign-in methods it offers, shortly after the address stops changing.
    var providers by remember { mutableStateOf<List<SsoProvider>>(emptyList()) }
    var localLogin by remember { mutableStateOf(true) }
    // Bumped after the user approves a certificate, so the probe runs again.
    var probeKey by remember { mutableStateOf(0) }
    LaunchedEffect(server, probeKey) {
        providers = emptyList(); localLogin = true; probeCert = null
        // SSO only over https: the ticket and session token must not cross the network in the clear.
        if (server.isBlank() || insecure) return@LaunchedEffect
        delay(600)
        runCatching { container.clientFor(server).status() }.onSuccess {
            providers = it.sso
            localLogin = it.localLogin || it.sso.isEmpty()
        }.onFailure { probeCert = HttpClients.untrustedCertificate(it) }
    }

    fun startSso(provider: SsoProvider) {
        error = null
        container.ssoError.value = null
        runCatching { container.startSso(context, server, provider) }
            .onFailure { error = it.userMessage() }
    }

    fun signIn() {
        if (busy) return
        busy = true; error = null
        scope.launch {
            val result = runCatching {
                val base = ApiClient.normalizeBaseUrl(server).toString()
                val user = username.trim()
                val login = container.clientFor(server).login(user, password, container.store.deviceTokenFor(base, user))
                container.store.saveDeviceToken(base, user, login.device)
                val status = runCatching { container.clientFor(server, login.token).status() }.getOrNull()
                container.onSignedIn(
                    server, username.trim(), login.token,
                    unlocked = login.unlocked ?: status?.unlocked ?: true,
                    expiresAt = login.expiresAt,
                )
            }
            busy = false
            result.onSuccess {
                password = ""
                onSignedIn()
            }.onFailure { e ->
                val cert = HttpClients.untrustedCertificate(e)
                if (cert != null) untrusted = cert else error = e.userMessage()
            }
        }
    }

    untrusted?.let { cert ->
        AlertDialog(
            onDismissRequest = { untrusted = null },
            title = { GuardDialogTouches(); Text("Trust this server's certificate?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Your phone doesn't recognise the certificate this server uses. That's normal for a " +
                        "self-signed certificate on a home server, but it's also what an attacker's would look like.")
                    Text("Only trust it if this SHA-256 fingerprint matches the one your server shows " +
                        "(for example in DSM under Security → Certificate):")
                    Text(cert.fingerprint, style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace))
                    Text(cert.subject, style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    cert.pinKey?.let(container.store::addPin)
                    untrusted = null
                    probeCert = null
                    probeKey++
                    if (localLogin && password.isNotEmpty()) signIn()
                }) { Text(if (localLogin && password.isNotEmpty()) "Trust and sign in" else "Trust") }
            },
            dismissButton = { TextButton(onClick = { untrusted = null }) { Text("Cancel") } },
        )
    }

    Scaffold { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(Icons.Default.Lock, contentDescription = null, tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(top = 48.dp))
            Text("ScanVault", style = MaterialTheme.typography.headlineMedium)
            Text(
                "Connect to your self-hosted ScanVault server.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = server,
                onValueChange = { server = it },
                label = { Text("Server address") },
                placeholder = { Text("https://scanvault.example.com") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Next),
                supportingText = if (insecure) {
                    { Text("Unencrypted http: anyone on the network can read your password and records.",
                        color = MaterialTheme.colorScheme.error) }
                } else null,
                modifier = Modifier.fillMaxWidth(),
            )
            if (insecure) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        "Allow unencrypted http on my local network (home Wi-Fi or VPN only). " +
                            "The vault key is never sent over http.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.weight(1f),
                    )
                    Switch(checked = allowLanHttp, enabled = serverHost != null, onCheckedChange = {
                        allowLanHttp = it
                        container.store.lanHttpHost = if (it) serverHost else null
                    })
                }
            }
            probeCert?.let { cert ->
                TextButton(onClick = { untrusted = cert }) {
                    Text("This server's certificate isn't trusted by Android. Review it")
                }
            }
            providers.forEach { provider ->
                OutlinedButton(
                    onClick = { startSso(provider) },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.AutoMirrored.Filled.Login, contentDescription = null)
                    Text("  Continue with ${provider.name}")
                }
            }
            ssoError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (!localLogin) error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (providers.isNotEmpty() && localLogin) {
                Text("or sign in with a password", style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (localLogin) {
            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text("Username") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next, autoCorrectEnabled = false),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text("Password") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                modifier = Modifier.fillMaxWidth(),
            )
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(
                onClick = ::signIn,
                enabled = !busy && server.isNotBlank() && username.isNotBlank() && password.isNotEmpty(),
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (busy) "Signing in…" else "Sign in") }
            }
            TextButton(onClick = onOpenSettings) {
                Icon(Icons.Default.Palette, contentDescription = null)
                Text("  Appearance")
            }
        }
    }
}
