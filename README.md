# MedVault

Self-hosted, encrypted vault for medical imaging and lab results, with a native
Android app. MedVault used to be called ScanVault.

| Folder | What it is |
| --- | --- |
| [`server/`](server/) | The server and web app (Python, Docker image `ghcr.io/ryanbyte1701/medvault`). Start with [server/README.md](server/README.md). |
| [`android/`](android/) | The Android app (Kotlin + Jetpack Compose). See [android/README.md](android/README.md). |

Both folders keep their full history from the former `scanvault` and
`scanvault-android` repositories (`git log --follow` works across the move).

CI runs per folder: `.github/workflows/server.yml` for `server/**`, and
`android.yml` and `android-screenshots.yml` for `android/**`.
