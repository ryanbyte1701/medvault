package com.scanvault.android.data

import android.os.SystemClock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * App lock: patient data is hidden behind the phone's biometrics or screen-lock PIN on every
 * cold start and after the app has been in the background longer than the chosen timeout.
 * Trips the app itself starts (camera, file picker, sign-in browser, opening a report) get a
 * longer grace period so returning from them doesn't prompt again.
 */
class AppLock(private val timeoutMinutes: () -> Int) {
    private val _locked = MutableStateFlow(true)
    val locked: StateFlow<Boolean> = _locked.asStateFlow()

    private var backgroundedAt: Long? = null
    private var externalTripUntil = 0L

    fun onBackground() {
        backgroundedAt = SystemClock.elapsedRealtime()
    }

    fun onForeground() {
        val since = backgroundedAt ?: return
        backgroundedAt = null
        val now = SystemClock.elapsedRealtime()
        if (now <= externalTripUntil) { externalTripUntil = 0; return }
        if (now - since >= timeoutMinutes() * 60_000L) _locked.value = true
    }

    /** Call just before launching another app for a result the user is waiting on. */
    fun expectExternalTrip(graceMillis: Long = 10 * 60_000L) {
        externalTripUntil = SystemClock.elapsedRealtime() + graceMillis
    }

    fun unlock() { _locked.value = false }

    fun lockNow() { _locked.value = true }
}
