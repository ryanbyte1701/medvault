"""Google Drive and Box adapters against mocked HTTP APIs."""
import json

import responses

from app import targets


@responses.activate
def test_gdrive_resumable_upload_list_prune(tmp_path):
    responses.post("https://oauth2.googleapis.com/token", json={"access_token": "AT"})
    responses.post(
        "https://www.googleapis.com/upload/drive/v3/files",
        headers={"Location": "https://upload.example/session1"},
        status=200,
    )
    responses.put("https://upload.example/session1", status=308)
    responses.put("https://upload.example/session1", json={"id": "f1"}, status=200)
    files = [{"id": f"id{i}", "name": f"scanvault-backup-2026010{i}-000000Z.svb"} for i in range(3)]
    responses.get("https://www.googleapis.com/drive/v3/files", json={"files": files})
    for i in range(2):
        responses.delete(f"https://www.googleapis.com/drive/v3/files/id{i}", status=204)

    t = targets.make("gdrive", {"auth_mode": "oauth", "client_id": "c", "client_secret": "s", "refresh_token": "r", "folder_id": "FOLDER"})
    p = tmp_path / "x.svb"
    p.write_bytes(b"\0" * (9 * 1024 * 1024))  # > one 8 MiB chunk
    t.upload(p, "scanvault-backup-20260109-000000Z.svb")
    start = [c for c in responses.calls if c.request.url.startswith("https://www.googleapis.com/upload")][0]
    assert json.loads(start.request.body)["parents"] == ["FOLDER"]
    puts = [c for c in responses.calls if c.request.method == "PUT"]
    assert puts[0].request.headers["Content-Range"] == f"bytes 0-{8 * 1024 * 1024 - 1}/{9 * 1024 * 1024}"
    assert puts[1].request.headers["Content-Range"].endswith(f"/{9 * 1024 * 1024}")
    assert t.prune(1) == 2


@responses.activate
def test_box_refresh_token_rotates_and_chunked_upload(tmp_path):
    responses.post("https://api.box.com/oauth2/token", json={"access_token": "AT", "refresh_token": "NEW"})
    responses.post(
        "https://upload.box.com/api/2.0/files/upload_sessions",
        json={"part_size": 8 * 1024 * 1024, "session_endpoints": {"upload_part": "https://upload.box.com/s/1", "commit": "https://upload.box.com/s/1/commit"}},
    )
    responses.put("https://upload.box.com/s/1", json={"part": {"part_id": "a", "offset": 0, "size": 1}})
    responses.post("https://upload.box.com/s/1/commit", json={"entries": []}, status=201)
    saved = {}
    t = targets.make("box", {"auth_mode": "oauth", "client_id": "c", "client_secret": "s", "refresh_token": "OLD"}, saved.update)
    p = tmp_path / "big.svb"
    with open(p, "wb") as f:
        f.truncate(60 * 1024 * 1024)
    t.upload(p, "scanvault-backup-20260101-000000Z.svb")
    assert saved["refresh_token"] == "NEW"
    parts = [c for c in responses.calls if c.request.url == "https://upload.box.com/s/1"]
    assert len(parts) == 8 and parts[0].request.headers["Digest"].startswith("sha=")
    commit = [c for c in responses.calls if c.request.url.endswith("/commit")][0]
    assert len(json.loads(commit.request.body)["parts"]) == 8


@responses.activate
def test_box_ccg_small_upload(tmp_path):
    responses.post("https://api.box.com/oauth2/token", json={"access_token": "AT"})
    responses.post("https://upload.box.com/api/2.0/files/content", json={"entries": [{"id": "1"}]}, status=201)
    t = targets.make("box", {"auth_mode": "ccg", "client_id": "c", "client_secret": "s", "subject_type": "user", "subject_id": "42", "folder_id": "99"})
    p = tmp_path / "s.svb"
    p.write_bytes(b"abc")
    t.upload(p, "scanvault-backup-20260101-000000Z.svb")
    tok = responses.calls[0].request.body
    assert "client_credentials" in tok and "box_subject_id=42" in tok
    assert b'"parent": {"id": "99"}' in responses.calls[1].request.body
