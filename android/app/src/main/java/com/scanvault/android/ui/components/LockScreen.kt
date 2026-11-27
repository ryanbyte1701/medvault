package com.scanvault.android.ui.components

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.scanvault.android.data.AppLock

/** Biometrics or the phone's PIN/pattern/password, whichever the phone supports. */
fun lockAuthenticators(): Int =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) BIOMETRIC_STRONG or DEVICE_CREDENTIAL
    else BIOMETRIC_WEAK or DEVICE_CREDENTIAL

/** Whether the phone has a PIN, pattern or password at all (biometrics need one too). */
fun phoneHasScreenLock(context: Context): Boolean =
    (context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceSecure

private fun canUseBiometricPrompt(activity: FragmentActivity): Boolean =
    BiometricManager.from(activity).canAuthenticate(lockAuthenticators()) == BiometricManager.BIOMETRIC_SUCCESS

/**
 * Full-screen, opaque lock that covers (and blocks touches to) everything underneath until
 * the user authenticates with the phone's biometrics or screen lock.
 */
@Composable
fun LockScreen(lock: AppLock) {
    val activity = LocalContext.current as FragmentActivity
    var message by remember { mutableStateOf<String?>(null) }
    // Only a phone with no screen lock at all opens without a check; Settings warns about it.
    val hasLock = remember { phoneHasScreenLock(activity) }
    // Fallback for phones where BiometricPrompt can't offer the device credential (some API 26-29).
    val confirmCredential = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) lock.unlock() else message = "Not unlocked"
    }

    fun prompt() {
        if (!hasLock) { lock.unlock(); return }
        message = null
        if (!canUseBiometricPrompt(activity)) {
            val keyguard = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            @Suppress("DEPRECATION")
            val intent = keyguard.createConfirmDeviceCredentialIntent("Unlock ScanVault",
                "Medical records are protected by your screen lock")
            if (intent != null) confirmCredential.launch(intent) else message = "This phone's screen lock can't be checked"
            return
        }
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = lock.unlock()
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    message = errString.toString()
                }
            },
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock ScanVault")
                .setSubtitle("Medical records are protected by your screen lock")
                .setAllowedAuthenticators(lockAuthenticators())
                .build(),
        )
    }

    LaunchedEffect(Unit) { prompt() }

    Column(
        Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            // Swallow touches so nothing underneath can be operated.
            .clickable(interactionSource = remember { MutableInteractionSource() }, indication = null) {}
            .padding(32.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Default.Lock, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(48.dp))
        Text("ScanVault is locked", style = MaterialTheme.typography.headlineSmall)
        message?.let { Text(it, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        Button(onClick = ::prompt) { Text("Unlock") }
    }
}
