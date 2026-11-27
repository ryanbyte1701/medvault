package com.scanvault.android

import android.app.Application
import coil.ImageLoader
import coil.ImageLoaderFactory
import com.scanvault.android.data.AppContainer

class ScanVaultApp : Application(), ImageLoaderFactory {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        val keyguard = getSystemService(KEYGUARD_SERVICE) as android.app.KeyguardManager
        com.scanvault.android.data.crypto.Keystore.deviceSecure = { keyguard.isDeviceSecure }
        container = AppContainer(this)
        // Decrypted copies opened in other apps are temporary; clear any left from a previous run.
        container.cleanUpOnLaunch()
    }

    override fun newImageLoader(): ImageLoader = container.imageLoader
}
