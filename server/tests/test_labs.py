"""LabsVault: parsing fictional Labcorp / Sonora Quest reports, review, save,
graph data, and that lab data is encrypted, re-keyed and backed up."""
import shutil

import pytest
from fastapi.testclient import TestClient

import lab_samples
from conftest import SETUP

from app import labcatalog, labparse, main
from app.store import Store

PASS = "lantern-orbit-cedar-quill-x"
PW = "pw-1234567890"
ocr = pytest.mark.skipif(shutil.which("tesseract") is None, reason="tesseract not installed")


@pytest.fixture()
def vault(tmp_path):
    old = main.store
    main.store = Store(tmp_path / "data")
    main.vault.lock()
    main._state["setup_code"] = None
    main._state["maintenance"] = None
    main._clear_caches()
    try:
        with TestClient(main.app) as c:
            r = c.post("/api/setup", json={"username": "ryan", "password": PW, "passphrase": PASS}, headers=SETUP)
            assert r.status_code == 200, r.text
            j = r.json()
            yield c, {"Authorization": f"Bearer {j['token']}"}, j
    finally:
        main.store = old
        main.vault.lock()


def _by(results, key):
    return next(r for r in results if r["analyte"] == key)


# ------------------------------------------------------------------ parser


def test_parse_labcorp():
    r = labparse.parse(lab_samples.labcorp())
    assert r["lab"] == "labcorp" and r["method"] == "text" and r["table_header"]
    f = r["fields"]
    assert f["collected"] == "2026-03-14" and f["reported"] == "2026-03-16" and f["dob"] == "1980-04-02"
    assert f["specimen_id"] == "073-494-1234-0" and f["patient_name"] == "DOE, JANE"
    res = r["results"]
    assert len(res) == 32
    g = _by(res, "glucose")
    assert (g["value"], g["value_num"], g["flag"], g["unit"], g["ref_low"], g["ref_high"]) == ("104", 104.0, "H", "mg/dL", 70.0, 99.0)
    assert (g["prev_value"], g["prev_date"], g["lab_code"], g["loinc"]) == ("97", "2025-09-20", "01", "2345-7")
    assert g["panel"] == "Comp. Metabolic Panel (14)"
    e = _by(res, "egfr")
    assert e["ref_low"] == 59 and e["ref_high"] is None and e["unit"] == "mL/min/1.73"
    assert _by(res, "ldl")["flag"] == "H" and _by(res, "platelets")["flag"] == "L"
    assert _by(res, "neutrophils_pct")["ref_text"] == "Not Estab."
    assert _by(res, "vitamin_d")["value_num"] == 24.1
    assert all(x["confidence"] == "high" for x in res)
    assert not any("please" in x["name"].lower() for x in res)


def test_parse_labcorp_classic():
    r = labparse.parse(lab_samples.labcorp_classic())
    assert r["lab"] == "labcorp" and r["fields"]["patient_name"] == "ROE, SAM"
    t = _by(r["results"], "tsh")
    assert (t["value"], t["flag"], t["unit"], t["ref_low"], t["ref_high"]) == ("5.120", "H", "uIU/mL", 0.45, 4.5)
    assert _by(r["results"], "t4_free")["flag"] is None
    assert _by(r["results"], "ferritin")["flag"] == "L"


def test_parse_sonora_quest():
    r = labparse.parse(lab_samples.sonora_quest())
    assert r["lab"] == "sonora_quest" and r["lab_name"] == "Sonora Quest Laboratories"
    f = r["fields"]
    assert f["collected"] == "2026-06-09" and f["specimen_id"] == "SQ123456A" and f["patient_name"] == "DOE, JANE"
    res = r["results"]
    assert len(res) == 20
    g = _by(res, "glucose")
    assert (g["value_num"], g["flag"], g["unit"], g["ref_low"], g["ref_high"], g["lab_code"]) == (108, "H", "mg/dL", 65, 99, "SQ")
    assert _by(res, "egfr")["ref_low"] == 60 and _by(res, "egfr")["unit"] == "mL/min/1.73m2"
    assert _by(res, "cholesterol_total")["ref_high"] == 200
    ldl = _by(res, "ldl")
    assert ldl["unit"] == "mg/dL" and ldl.get("ref_text") is None
    assert _by(res, "vitamin_d")["flag"] == "L" and _by(res, "hba1c")["unit"] == "%"
    assert not any(x["analyte"].startswith("x_") for x in res)


@ocr
def test_parse_scanned_report_with_ocr():
    r = labparse.parse(lab_samples.scanned(lab_samples.labcorp()))
    assert r["method"] == "ocr" and r["lab"] == "labcorp"
    assert any("OCR" in w for w in r["warnings"])
    assert r["fields"]["collected"] == "2026-03-14"
    vals = {x["analyte"]: x["value"] for x in r["results"]}
    assert len(vals) >= 28
    assert vals["glucose"] == "104" and vals["hba1c"] == "5.9" and vals["ldl"] == "131"


def test_ref_value_and_name_helpers():
    assert labparse.parse_ref("< OR = 99 mg/dL")["high"] == 99
    assert labparse.parse_ref("> OR = 60")["low"] == 60
    assert labparse.parse_ref("0.450-4.500")["low"] == 0.45
    assert labparse.parse_value("221H")["flag"] == "H"
    assert labparse.parse_value("Non Reactive")["value"] == "Non Reactive"
    assert labparse.parse_value("<0.5")["comparator"] == "<"
    assert labparse.parse_value("hello") is None
    assert labcatalog.lookup("VITAMIN D,25-OH, TOTAL,IA") == "vitamin_d"
    assert labcatalog.lookup("Hemoglobin Aic") == "hba1c"
    assert labcatalog.lookup("Glucose 01") == "glucose"
    assert labcatalog.lookup("Something Rare") is None and labcatalog.key_for("Something Rare") == "x_something_rare"


def test_parse_rejects_garbage():
    with pytest.raises(labparse.ParseError):
        labparse.parse(b"%PDF-1.4 not really")


# ------------------------------------------------------------------ API


def _patient(c, B, **kw):
    return c.post("/api/patients", json={"name": "Jane Doe", "date_of_birth": "1980-04-02", **kw}, headers=B).json()


def _upload(c, B, pid, pdf, name="labs.pdf"):
    r = c.post(f"/api/patients/{pid}/labs/upload", files=[("file", (name, pdf, "application/pdf"))], headers=B)
    assert r.status_code == 200, r.text
    return r.json()


def test_upload_review_save_and_graph(vault):
    c, B, _ = vault
    p = _patient(c, B)
    pdf = lab_samples.labcorp()
    d = _upload(c, B, p["id"], pdf)
    assert d["status"] == "draft" and d["lab"] == "labcorp" and d["collected"] == "2026-03-14"
    assert len(d["rows"]) == 32 and d["file_id"] and not d["warnings"]
    # drafts are not graphed yet
    assert c.get(f"/api/patients/{p['id']}/labs/analytes", headers=B).json() == []
    # the PDF is in the patient's records, in a lab report study
    studies = c.get(f"/api/patients/{p['id']}/studies", headers=B).json()
    assert studies[0]["title"] == "Labcorp lab report" and studies[0]["modality"] == "LAB" and studies[0]["study_date"] == "2026-03-14"
    assert c.get(f"/api/files/{d['file_id']}/content", headers=B).content[:4] == b"%PDF"
    # same file again: the existing report comes back
    again = _upload(c, B, p["id"], pdf)
    assert again["duplicate"] and again["id"] == d["id"]
    # review: fix a value, drop a row, add one by hand
    rows = d["rows"]
    rows[0]["value"] = "105"
    rows[1]["include"] = False
    rows.append({"name": "Magnesium", "value": "2.1", "unit": "mg/dL", "ref_low": 1.6, "ref_high": 2.3, "source": "manual"})
    r = c.put(f"/api/labs/reports/{d['id']}", json={"rows": rows, "save": True}, headers=B)
    assert r.status_code == 200, r.text
    s = r.json()
    assert s["status"] == "saved" and s["result_count"] == 32
    assert c.get(f"/api/patients/{p['id']}/labs/reports", headers=B).json()[0]["status"] == "saved"

    an = {a["key"]: a for a in c.get(f"/api/patients/{p['id']}/labs/analytes", headers=B).json()}
    assert "bun" not in an and an["magnesium"]["count"] == 1
    assert an["glucose"]["latest"]["value"] == "105" and an["glucose"]["count"] == 2  # + previous result column
    assert an["glucose"]["loinc"] == "2345-7"

    # a later Sonora Quest report adds a point to the same series
    d2 = _upload(c, B, p["id"], lab_samples.sonora_quest())
    assert c.put(f"/api/labs/reports/{d2['id']}", json={"save": True}, headers=B).status_code == 200
    ser = c.get(f"/api/patients/{p['id']}/labs/analytes/glucose", headers=B).json()
    assert [(x["date"], x["value_num"], x["source"]) for x in ser["points"]] == [
        ("2025-09-20", 97.0, "previous"), ("2026-03-14", 105.0, "report"), ("2026-06-09", 108.0, "report")]
    assert ser["points"][-1]["ref_high"] == 99 and ser["points"][-1]["lab_name"] == "Sonora Quest Laboratories"
    assert ser["units"] == ["mg/dL"]

    csv = c.get(f"/api/patients/{p['id']}/labs/export.csv", headers=B)
    assert csv.status_code == 200 and "attachment" in csv.headers["content-disposition"]
    assert "2026-06-09,Glucose,2345-7,108,mg/dL,H,65.0,99.0" in csv.text

    # delete the first report: its values and its PDF go
    assert c.delete(f"/api/labs/reports/{d['id']}", headers=B).json()["ok"]
    assert [x["date"] for x in c.get(f"/api/patients/{p['id']}/labs/analytes/glucose", headers=B).json()["points"]] == ["2026-06-09"]
    assert c.get(f"/api/files/{d['file_id']}", headers=B).status_code == 404
    assert "Labcorp lab report" not in [s["title"] for s in c.get(f"/api/patients/{p['id']}/studies", headers=B).json()]


def test_lab_data_is_encrypted_at_rest(vault):
    c, B, _ = vault
    p = _patient(c, B)
    d = _upload(c, B, p["id"], lab_samples.sonora_quest())
    c.put(f"/api/labs/reports/{d['id']}", json={"save": True}, headers=B)
    db = (main.store.dir / "scanvault.db").read_bytes()
    for wal in main.store.dir.glob("scanvault.db-wal"):
        db += wal.read_bytes()
    for needle in (b"Sonora", b"GLUCOSE", b"glucose", b"mg/dL", b"SQ123456A", b"2026-06-09"):
        assert needle not in db


def test_patient_mismatch_warning(vault):
    c, B, _ = vault
    p = c.post("/api/patients", json={"name": "Sam Roe", "date_of_birth": "1990-01-01"}, headers=B).json()
    d = _upload(c, B, p["id"], lab_samples.labcorp())
    assert any("date of birth" in w for w in d["warnings"])


def test_manual_report_and_validation(vault):
    c, B, _ = vault
    p = _patient(c, B)
    base = f"/api/patients/{p['id']}/labs/reports"
    assert c.post(base, json={"lab": "other", "rows": [{"name": "Glucose", "value": "90"}], "save": True}, headers=B).status_code == 400  # no date
    assert c.post(base, json={"collected": "2026-01-05", "rows": [{"name": "Glucose"}], "save": True}, headers=B).status_code == 400
    assert c.post(base, json={"collected": "2026-01-05", "rows": [{"name": "Glucose", "value": "90", "flag": "X"}], "save": True}, headers=B).status_code == 400
    assert c.post(base, json={"collected": "2026-01-05", "rows": [{"name": "Glucose", "value": "90", "ref_low": 99, "ref_high": 70}], "save": True}, headers=B).status_code == 400
    assert c.post(base, json={"collected": "2026-01-05", "rows": [{"name": "Glucose", "value": "90", "analyte": "../etc"}], "save": True}, headers=B).status_code == 400
    r = c.post(base, json={"collected": "2026-01-05", "lab_name": "Clinic", "rows": [{"name": "Glucose", "value": "90", "unit": "mg/dL"}, {"name": "Strep A", "value": "Negative"}], "save": True}, headers=B)
    assert r.status_code == 200, r.text
    an = {a["key"]: a for a in c.get(f"/api/patients/{p['id']}/labs/analytes", headers=B).json()}
    assert an["glucose"]["latest"]["value_num"] == 90 and an["x_strep_a"]["latest"]["value"] == "Negative"
    # a saved report needs save: true to change its results
    assert c.put(f"/api/labs/reports/{r.json()['id']}", json={"rows": []}, headers=B).status_code == 400


def test_labs_need_auth_and_reject_other_files(vault):
    c, B, _ = vault
    p = _patient(c, B)
    c.cookies.clear()
    assert c.get(f"/api/patients/{p['id']}/labs/analytes").status_code == 401
    r = c.post(f"/api/patients/{p['id']}/labs/upload", files=[("file", ("x.txt", b"hello"))], headers=B)
    assert r.status_code == 400
    assert c.get("/api/labs/reports/nope", headers=B).status_code == 404
    info = c.get("/api/labs/info", headers=B).json()
    assert any(a["key"] == "glucose" for a in info["catalog"])


def test_labs_survive_rekey_and_restore(vault):
    c, B, j = vault
    p = _patient(c, B)
    d = _upload(c, B, p["id"], lab_samples.labcorp_classic())
    assert c.put(f"/api/labs/reports/{d['id']}", json={"save": True}, headers=B).status_code == 200
    r = c.post("/api/vault/rekey", json={"passphrase": PASS, "new_passphrase": "rotated-quartz-passphrase-9"}, headers=B)
    assert r.status_code == 200, r.text
    assert c.get(f"/api/patients/{p['id']}/labs/analytes/tsh", headers=B).json()["points"][0]["value"] == "5.120"
    assert c.get(f"/api/labs/reports/{d['id']}", headers=B).json()["lab_name"] == "Labcorp"
    svb = c.get("/api/backups/download", headers=B).content
    assert c.delete(f"/api/labs/reports/{d['id']}", headers=B).status_code == 200
    assert c.get(f"/api/patients/{p['id']}/labs/analytes", headers=B).json() == []
    r = c.post("/api/backups/restore", files={"backup_file": ("b.svb", svb)}, data={"confirm": "REPLACE"}, headers=B)
    assert r.status_code == 200, r.text
    ser = c.get(f"/api/patients/{p['id']}/labs/analytes/tsh", headers=B).json()
    assert ser["points"][0]["value_num"] == 5.12
    rep = c.get(f"/api/labs/reports/{d['id']}", headers=B).json()
    assert c.get(f"/api/files/{rep['file_id']}/content", headers=B).content[:4] == b"%PDF"


def test_emergency_restore_exports_lab_results(vault, tmp_path):
    import subprocess
    import sys

    from conftest import ROOT

    c, B, j = vault
    p = _patient(c, B)
    d = _upload(c, B, p["id"], lab_samples.sonora_quest())
    c.put(f"/api/labs/reports/{d['id']}", json={"save": True}, headers=B)
    svb = tmp_path / "b.svb"
    svb.write_bytes(c.get("/api/backups/download", headers=B).content)
    keyf = tmp_path / "key.txt"
    keyf.write_text(j["recovery_key"])
    out = tmp_path / "out"
    cp = subprocess.run([sys.executable, str(ROOT / "tools" / "restore.py"), "--backup", str(svb), "--key", str(keyf), "--out", str(out)], capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    csv_text = next(out.glob("*/lab-results.csv")).read_text()
    assert "2026-06-09,GLUCOSE,2345-7,108,mg/dL,H,65.0,99.0" in csv_text
    assert next(out.glob("*/*/*.pdf")).read_bytes()[:4] == b"%PDF"


def test_lab_actions_reach_the_activity_log(vault, monkeypatch):
    c, B, _ = vault
    seen = []
    monkeypatch.setattr(main, "log_event", lambda request, action, **kw: seen.append((action, kw)), raising=False)
    p = _patient(c, B)
    d = _upload(c, B, p["id"], lab_samples.labcorp_classic())
    c.put(f"/api/labs/reports/{d['id']}", json={"save": True}, headers=B)
    c.get(f"/api/patients/{p['id']}/labs/export.csv", headers=B)
    c.delete(f"/api/labs/reports/{d['id']}", headers=B)
    seen = [(a, kw) for a, kw in seen if a.startswith("lab.")]  # the app's own events (patient.create...) go through it too
    assert [a for a, _ in seen] == ["lab.upload", "lab.save", "lab.export", "lab.delete"]
    assert all(kw["patient_id"] == p["id"] for _, kw in seen)
    assert "5.120" not in repr(seen)  # no lab values in the log


def test_patient_record_counts_scans_and_labs(vault):
    """A patient record holds both: imaging studies (Scans) and lab reports (Labs)."""
    c, B, _ = vault
    p = _patient(c, B)
    c.post(f"/api/patients/{p['id']}/studies", json={"title": "MRI left knee", "modality": "MR"}, headers=B)
    got = c.get(f"/api/patients/{p['id']}", headers=B).json()
    assert (got["scan_count"], got["lab_report_count"], got["lab_draft_count"]) == (1, 0, 0)
    d = _upload(c, B, p["id"], lab_samples.labcorp())
    got = c.get(f"/api/patients/{p['id']}", headers=B).json()
    # the report's PDF is filed in a LAB study, which is not a scan
    assert (got["study_count"], got["scan_count"], got["lab_report_count"], got["lab_draft_count"]) == (2, 1, 0, 1)
    assert c.put(f"/api/labs/reports/{d['id']}", json={"save": True}, headers=B).status_code == 200
    listed = {x["id"]: x for x in c.get("/api/patients", headers=B).json()}[p["id"]]
    assert (listed["scan_count"], listed["lab_report_count"], listed["lab_draft_count"]) == (1, 1, 0)
