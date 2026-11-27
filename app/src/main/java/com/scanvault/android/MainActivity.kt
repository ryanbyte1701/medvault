package com.scanvault.android

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.scanvault.android.ui.ScanVaultNavHost
import com.scanvault.android.ui.theme.ScanVaultTheme
import com.scanvault.android.ui.theme.isAppInDarkTheme

/** FragmentActivity (a ComponentActivity) because the app lock uses BiometricPrompt. */
class MainActivity : FragmentActivity() {
    private val container get() = (application as ScanVaultApp).container

    override fun onCreate(savedInstanceState: Bundle?) {
        // Keep patient data out of Recents thumbnails, screenshots and screen recordings.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        stripUntrustedExtras(intent)
        enableEdgeToEdge()
        // Ignore taps that pass through an overlay drawn by another app (tapjacking).
        window.decorView.filterTouchesWhenObscured = true
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
            ScanVaultTheme(settings) {
                ScanVaultNavHost(container)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        stripUntrustedExtras(intent)
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
