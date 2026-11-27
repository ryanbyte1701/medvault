package com.scanvault.android.screenshots

import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import com.github.takahirom.roborazzi.captureRoboImage
import com.scanvault.android.MainActivity
import com.scanvault.android.ScanVaultApp
import com.scanvault.android.data.AppContainer
import com.scanvault.android.data.ThemeMode
import org.junit.After
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.io.File

/**
 * Renders the real app against [SampleServer] (fictional sample vault) in the dark theme and saves
 * the images used in the README. Run with:
 *
 *     ./gradlew testDebugUnitTest -Pscreenshots --tests '*screenshots*'
 *
 * Output: app/build/screenshots/<name>.png
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-night-xxhdpi")
class ReadmeScreenshots {
    @get:Rule val compose = createEmptyComposeRule()

    private val server = SampleServer()
    private var scenario: ActivityScenario<MainActivity>? = null

    companion object {
        @JvmStatic @BeforeClass fun keystore() = FakeAndroidKeyStore.install()
        init { FakeAndroidKeyStore.install() }
    }

    private val outDir = File(System.getProperty("scanvault.screenshots.dir") ?: "build/screenshots").apply { mkdirs() }

    private fun container(): AppContainer =
        ApplicationProvider.getApplicationContext<ScanVaultApp>().container

    @After fun tearDown() {
        scenario?.close()
        server.shutdown()
    }

    /** Lets network calls and image loads (which run on real threads) finish and recompose. */
    private fun settle(ms: Long = 2500) {
        val end = System.currentTimeMillis() + ms
        while (System.currentTimeMillis() < end) {
            compose.waitForIdle()
            Thread.sleep(100)
        }
        compose.waitForIdle()
    }

    private fun shot(name: String) {
        settle()
        compose.onRoot().captureRoboImage(File(outDir, "$name.png").path)
    }

    private fun clickAny(text: String) {
        compose.onAllNodes(hasText(text, substring = true), useUnmergedTree = true)[0].performClick()
        settle()
    }

    private fun signedIn() {
        val url = server.start()
        val c = container()
        c.store.allowLanHttp = true
        c.theme.update { it.copy(mode = ThemeMode.DARK, darkColor = "#0d1416") }
        c.onSignedIn(url, "ryan", "sample-token", unlocked = true)
        c.appLock.unlock()
        // Robolectric can't draw hardware bitmaps, so thumbnails need software ones.
        coil.Coil.setImageLoader(c.imageLoader.newBuilder().allowHardware(false).build())
        scenario = ActivityScenario.launch(MainActivity::class.java)
        settle()
    }

    @Test fun signIn() {
        val c = container()
        c.theme.update { it.copy(mode = ThemeMode.DARK, darkColor = "#0d1416") }
        c.store.serverUrl = "https://scanvault.example.com/"
        c.store.username = "ryan"
        scenario = ActivityScenario.launch(MainActivity::class.java)
        settle()
        compose.onAllNodes(hasText("Password") and hasSetTextAction())[0].performTextInput("sample-password")
        shot("android-sign-in")
    }

    @Test fun browseVault() {
        signedIn()
        shot("android-patients")
        clickAny("Jane Doe")
        shot("android-patient")
        clickAny("CT chest with contrast")
        settle(3000)
        shot("android-study")
        compose.onAllNodes(hasContentDescription("IM000003.dcm"), useUnmergedTree = true)[0].performClick()
        settle(4000)
        shot("android-viewer")
    }

    @Test fun settings() {
        signedIn()
        compose.onNode(hasContentDescription("Settings")).performClick()
        settle()
        shot("android-settings")
    }
}
