package com.scanvault.android.screenshots

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okio.Buffer

/**
 * A stand-in ScanVault server for the screenshot tests. It serves the same fictional sample vault
 * as the web app's demo (src/test/resources/sample-vault, exported from tools/demo/demo.js in the
 * server repo): no real patient data.
 */
class SampleServer {
    private val vault: JsonObject = Json.parseToJsonElement(resource("vault.json").decodeToString()).jsonObject
    private val patients = vault["patients"]!!.jsonArray
    private val studies = vault["studies"]!!.jsonObject.values.flatMap { it.jsonArray }
    private val files = vault["files"]!!.jsonObject.values.flatMap { it.jsonArray }

    val server = MockWebServer().apply {
        dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = route(request)
        }
    }

    fun start(): String {
        server.start()
        return "http://localhost:${server.port}"
    }

    fun shutdown() = server.shutdown()

    private fun route(req: RecordedRequest): MockResponse {
        val path = req.requestUrl!!.encodedPath
        println("sample-server: ${req.method} $path")
        val parts = path.trim('/').split('/')
        return when {
            path == "/api/status" -> json(
                """{"setup_complete":true,"unlocked":true,"authenticated":true,"username":"ryan",""" +
                    """"vault_id":"SV-7F3A91C2","fingerprint":"8C1E-55D0-A7F2-0B94","version":"0.1.0","local_login":true,""" +
                    """"sso":[{"id":"google","name":"Google","preset":"google"}]}""",
            )
            path == "/api/prefs" -> json("""{"theme":"dark","dark_color":"#0d1416"}""")
            path == "/api/patients" -> json(patients.toString())
            parts.size == 3 && parts[1] == "patients" -> json(byId(patients, parts[2]))
            parts.size == 4 && parts[1] == "patients" && parts[3] == "studies" ->
                json(JsonArray(studies.filter { it.str("patient_id") == parts[2] }).toString())
            parts.size == 3 && parts[1] == "studies" -> json(byId(studies, parts[2]))
            parts.size == 4 && parts[1] == "studies" && parts[3] == "files" ->
                json(JsonArray(files.filter { it.str("study_id") == parts[2] }).toString())
            parts.size == 4 && parts[1] == "files" && parts[3] == "thumbnail" -> image("thumb-${parts[2]}.jpg")
            parts.size == 4 && parts[1] == "files" && parts[3] == "content" -> image("thumb-${parts[2]}.jpg")
            parts.size == 4 && parts[1] == "files" && parts[3] == "render" ->
                image("render-${parts[2]}.jpg")
                    .setHeader("X-Window-Center", req.requestUrl!!.queryParameter("wc") ?: "-600")
                    .setHeader("X-Window-Width", req.requestUrl!!.queryParameter("ww") ?: "1500")
                    .setHeader("X-Default-Center", "-600")
                    .setHeader("X-Default-Width", "1500")
                    .setHeader("X-Min", "-1024")
                    .setHeader("X-Max", "2400")
                    .setHeader("X-Frames", "1")
                    .setHeader("X-Modality", "CT")
            else -> MockResponse().setResponseCode(404).setBody("""{"error":"Not in the sample vault: $path"}""")
        }
    }

    private fun kotlinx.serialization.json.JsonElement.str(key: String) = jsonObject[key]?.jsonPrimitive?.content

    private fun byId(list: List<kotlinx.serialization.json.JsonElement>, id: String) =
        list.firstOrNull { it.str("id") == id }?.toString() ?: "{}"

    private fun json(body: String) =
        MockResponse().setHeader("Content-Type", "application/json").setBody(body)

    private fun image(name: String): MockResponse {
        val bytes = runCatching { resource("img/$name") }.getOrNull()
            ?: return MockResponse().setResponseCode(404).setBody("""{"error":"no image"}""")
        return MockResponse().setHeader("Content-Type", "image/jpeg").setBody(Buffer().write(bytes))
    }

    private fun resource(name: String): ByteArray =
        javaClass.classLoader!!.getResourceAsStream("sample-vault/$name")?.use { it.readBytes() }
            ?: error("missing sample-vault/$name")
}
