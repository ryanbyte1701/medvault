package com.medvault.android.data

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
    private var tripRequestedAt: Long? = null
    private var tripGraceMillis = 0L
    private var onTrip = false

    fun onBackground() {
        val now = SystemClock.elapsedRealtime()
        backgroundedAt = now
        // Only a trip that actually leaves the app right after it was requested counts; a launch
        // that failed or was abandoned leaves no grace behind for a later, ordinary backgrounding.
        onTrip = tripRequestedAt?.let { now - it <= TRIP_START_WINDOW_MS } == true
        tripRequestedAt = null
    }

    fun onForeground() {
        val since = backgroundedAt ?: return
        backgroundedAt = null
        val away = SystemClock.elapsedRealtime() - since
        val trip = onTrip
        onTrip = false
        val allowed = if (trip) maxOf(tripGraceMillis, timeoutMillis()) else timeoutMillis()
        if (away >= allowed) _locked.value = true
    }

    private fun timeoutMillis() = timeoutMinutes() * 60_000L

    /**
     * Call just before launching another app for a result the user is waiting on (camera, file
     * picker, report viewer, sign-in browser). That one trip may last up to [graceMillis].
     */
    fun expectExternalTrip(graceMillis: Long = 10 * 60_000L) {
        tripRequestedAt = SystemClock.elapsedRealtime()
        tripGraceMillis = graceMillis
    }

    /** Call when a launch prepared with [expectExternalTrip] didn't happen. */
    fun cancelExternalTrip() { tripRequestedAt = null }

    fun unlock() { _locked.value = false }

    fun lockNow() { _locked.value = true }

    private companion object {
        const val TRIP_START_WINDOW_MS = 5_000L
    }
}
