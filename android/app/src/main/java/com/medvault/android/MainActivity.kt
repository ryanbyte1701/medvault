package com.medvault.android

import android.content.Intent
import android.graphics.Color
import com.medvault.android.data.SsoResult
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.medvault.android.ui.MedVaultNavHost
import com.medvault.android.ui.theme.MedVaultTheme
import com.medvault.android.ui.theme.isAppInDarkTheme

/** FragmentActivity (a ComponentActivity) because the app lock uses BiometricPrompt. */
class MainActivity : FragmentActivity() {
    private val container get() = (application as MedVaultApp).container

    override fun onCreate(savedInstanceState: Bundle?) {
        // Keep patient data out of Recents thumbnails, screenshots and screen recordings.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        stripUntrustedExtras(intent)
        enableEdgeToEdge()
        // Ignore taps that pass through an overlay drawn by another app (tapjacking).
        window.decorView.filterTouchesWhenObscured = true
        handleSsoIntent(intent)
        setContent {
            val settings by container.theme.settings.collectAsStateWithLifecycle()
            val dark = isAppInDarkTheme(settings)
            // Keep status/navigation bar icons readable when the in-app theme differs from the system's.
            DisposableEffect(dark) {
                val style = if (dark) SystemBarStyle.dark(Color.TRANSPARENT)
                    else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                enableEdgeToEdge(statusBarStyle = style, navigationBarStyle = style)
                onDispose {}
            }
            MedVaultTheme(settings) {
                MedVaultNavHost(container)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        stripUntrustedExtras(intent)
        handleSsoIntent(intent)
    }

    /**
     * Hands a medvault://sso redirect from the browser to the container, which ignores it
     * unless it answers the sign-in this app started.
     */
    private fun handleSsoIntent(intent: Intent?) {
        val data = intent?.data ?: return
        val result = SsoResult.parse(data) ?: return
        container.offerSsoCallback(result)
        intent.data = null // don't replay it after rotation
    }

    override fun onStart() {
        super.onStart()
        container.appLock.onForeground()
        container.checkExpiry()
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) container.appLock.onBackground()
    }

    /**
     * The launcher activity is exported, so another app could start it with Navigation's
     * deep-link extras to jump to an arbitrary screen. Drop every extra; the app uses none.
     */
    private fun stripUntrustedExtras(intent: Intent?) {
        intent?.replaceExtras(null as Bundle?)
        setIntent(intent)
    }
}
