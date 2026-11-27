"""LabsVault: lab results per patient, read from Labcorp / Quest / Sonora
Quest report PDFs (or entered by hand), reviewed by the user, then kept as
encrypted values that can be graphed over time.

Storage
  lab_reports  one row per report; everything but ids, status and times is
               sealed (lab, dates, provider, the draft rows while reviewing).
  lab_results  one row per saved value, sealed (analyte, value, unit, range,
               flag, date). Only saved reports have results.
The original PDF goes into the patient's records as a normal encrypted file
(in a "lab report" study), so it is viewable, backed up and re-keyed like
every other document.
"""
from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import logging
import re
import time

from fastapi import APIRouter, Request
from fastapi.responses import Response

from . import labcatalog as cat
from . import labparse, media
from . import main as M
from .store import seal, unseal

log = logging.getLogger("scanvault.labs")
router = APIRouter()

MAX_LAB_FILE = 50 * 1024 * 1024
MAX_ROWS = 400
FLAGS = ("H", "L", "HH", "LL", "A", "C")


def _activity(request: Request, action: str, **details) -> None:
    """Record in the activity log when the app has one (best effort)."""
    fn = getattr(M, "log_event", None)
    if fn is None:
        return
    try:
        fn(request, action, **details)
    except Exception:  # never fail the request over the log
        log.exception("activity log write failed")


# ------------------------------------------------------------------ helpers


def _report_row(rid: str):
    r = M.store.conn().execute("SELECT * FROM lab_reports WHERE id=?", (rid,)).fetchone()
    if not r:
        raise M.ApiError(404, "Lab report not found")
    return r


def _report_blob(row, master: bytes) -> dict:
    return unseal(master, row["blob"], f"labreport:{row['id']}")


def _result_blob(row, master: bytes) -> dict:
    return unseal(master, row["blob"], f"labresult:{row['id']}")


def _file_exists(fid: str | None) -> bool:
    return bool(fid) and M.store.conn().execute("SELECT 1 FROM files WHERE id=?", (fid,)).fetchone() is not None


REPORT_KEYS = ("lab", "lab_name", "collected", "received", "reported", "specimen_id", "ordering_provider", "fasting", "notes")


def _report_out(row, master: bytes, results: list[dict] | None = None, full: bool = False) -> dict:
    d = _report_blob(row, master)
    out = {
        "id": row["id"],
        "patient_id": row["patient_id"],
        "status": row["status"],
        "created_at": M.iso(row["created_at"]),
        "updated_at": M.iso(row["updated_at"]),
        "file_id": d.get("file_id") if _file_exists(d.get("file_id")) else None,
        "filename": d.get("filename"),
        "method": d.get("method"),
    }
    for k in REPORT_KEYS:
        out[k] = d.get(k)
    if results is None and row["status"] == "saved":
        results = _results_for(row["id"], master)
    rows = results if row["status"] == "saved" else d.get("rows", [])
    out["result_count"] = len([r for r in rows if r.get("source") != "previous"])
    out["flagged_count"] = len([r for r in rows if r.get("flag") and r.get("source") != "previous"])
    if full:
        out["rows"] = rows
        out["warnings"] = d.get("warnings", [])
        out["parsed_patient"] = d.get("parsed_patient")
    return out


def _results_for(rid: str, master: bytes) -> list[dict]:
    rows = M.store.conn().execute("SELECT * FROM lab_results WHERE report_id=? ORDER BY created_at", (rid,)).fetchall()
    out = []
    for r in rows:
        d = _result_blob(r, master)
        d["id"] = r["id"]
        out.append(d)
    out.sort(key=lambda d: d.get("order", 0))
    return out


def _num(v, what: str):
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        raise M.ApiError(400, f"{what} must be a number")
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise M.ApiError(400, f"{what} must be a number")
    if f != f or abs(f) > 1e12:
        raise M.ApiError(400, f"{what} must be a number")
    return f


def _clean_row(j: dict, i: int, collected: str | None) -> dict:
    if not isinstance(j, dict):
        raise M.ApiError(400, "Each result must be an object")
    name = M._str(j.get("name"), 120)
    value = M._str(j.get("value"), 60)
    if not name:
        raise M.ApiError(400, f"Result {i + 1} needs a test name")
    if not value:
        raise M.ApiError(400, f"{name} needs a value")
    key = M._str(j.get("analyte"), 64)
    if key and not (cat.info(key) or re.fullmatch(r"x_[a-z0-9_]{1,62}", key)):
        raise M.ApiError(400, f"Unknown analyte for {name}")
    key = key or cat.key_for(name)
    comp, num = labparse.parse_number(value)
    flag = M._str(j.get("flag"), 4)
    flag = flag.upper() if flag else None
    if flag and flag not in FLAGS:
        raise M.ApiError(400, f"Flag for {name} must be one of {', '.join(FLAGS)}")
    d = {
        "analyte": key,
        "name": name,
        "loinc": (cat.info(key) or {}).get("loinc"),
        "panel": M._str(j.get("panel"), 120),
        "value": value,
        "value_num": num,
        "comparator": comp,
        "unit": M._str(j.get("unit"), 40),
        "ref_low": _num(j.get("ref_low"), f"Low end of the range for {name}"),
        "ref_high": _num(j.get("ref_high"), f"High end of the range for {name}"),
        "ref_text": M._str(j.get("ref_text"), 80),
        "flag": flag,
        "date": M._valid_date(M._str(j.get("date"), 10), f"Date for {name}") or collected,
        "source": j.get("source") if j.get("source") in ("report", "manual", "previous") else "report",
        "order": i,
    }
    if j.get("prev_value") not in (None, "") and j.get("prev_date"):
        d["prev_value"] = M._str(j.get("prev_value"), 60)
        d["prev_date"] = M._valid_date(M._str(j.get("prev_date"), 10), f"Previous date for {name}")
    if d["ref_low"] is not None and d["ref_high"] is not None and d["ref_low"] > d["ref_high"]:
        raise M.ApiError(400, f"The range for {name} is backwards")
    return d


def _report_fields(j: dict, existing: dict) -> dict:
    d = dict(existing)
    for k in REPORT_KEYS:
        if k in j:
            d[k] = M._str(j[k], 2000 if k == "notes" else 200)
    for k in ("collected", "received", "reported"):
        if k in j:
            d[k] = M._valid_date(d.get(k), f"{k.capitalize()} date")
    if d.get("lab") and d["lab"] not in labparse.LABS and d["lab"] != "other":
        d["lab"] = "other"
    if "lab" in j and not j.get("lab_name"):
        d["lab_name"] = labparse.LABS.get(d.get("lab") or "", d.get("lab_name"))
    return d


def _draft_rows(parsed: dict) -> list[dict]:
    rows = []
    for i, r in enumerate(parsed.get("results", [])[:MAX_ROWS]):
        rows.append({
            "analyte": r["analyte"],
            "catalog": r.get("catalog", False),
            "name": r["name"],
            "loinc": r.get("loinc"),
            "panel": r.get("panel"),
            "value": r["value"],
            "value_num": r.get("value_num"),
            "unit": r.get("unit"),
            "ref_low": r.get("ref_low"),
            "ref_high": r.get("ref_high"),
            "ref_text": r.get("ref_text"),
            "flag": r.get("flag"),
            "flag_derived": r.get("flag_derived", False),
            "prev_value": r.get("prev_value"),
            "prev_date": r.get("prev_date"),
            "confidence": r.get("confidence"),
            "page": r.get("page"),
            "source": "report",
            "order": i,
        })
    return rows


def _norm_name(n: str | None) -> set[str]:
    return {t for t in re.split(r"[^a-z]+", (n or "").lower()) if len(t) > 1}


def _patient_warnings(patient: dict, fields: dict) -> list[str]:
    w = []
    dob, name = fields.get("dob"), fields.get("patient_name")
    if dob and patient.get("date_of_birth") and dob != patient["date_of_birth"]:
        w.append(f"The report's date of birth ({dob}) does not match {patient.get('name')}'s ({patient['date_of_birth']}). Check that this is the right patient.")
    elif name and patient.get("name") and not (_norm_name(name) & _norm_name(patient["name"])):
        w.append(f"The report is for {name}, which does not look like {patient.get('name')}. Check that this is the right patient.")
    return w


def _save_results(rid: str, pid: str, rows: list[dict], master: bytes, import_previous: bool) -> int:
    c = M.store.conn()
    c.execute("DELETE FROM lab_results WHERE report_id=?", (rid,))
    now = time.time()
    n = 0
    for r in rows:
        if r.get("source") == "previous":
            continue
        out = [r]
        if import_previous and r.get("prev_value") and r.get("prev_date"):
            comp, num = labparse.parse_number(r["prev_value"])
            p = {k: r.get(k) for k in ("analyte", "name", "loinc", "panel", "unit", "ref_low", "ref_high", "ref_text")}
            p.update(value=r["prev_value"], value_num=num, comparator=comp, date=r["prev_date"], source="previous", order=r.get("order", 0) + 0.5)
            p["flag"] = labparse._derive_flag(p)
            out.append(p)
        for d in out:
            xid = M.crypto.random_id() + M.crypto.random_id()
            c.execute(
                "INSERT INTO lab_results(id,report_id,patient_id,created_at,blob) VALUES(?,?,?,?,?)",
                (xid, rid, pid, now, seal(master, d, f"labresult:{xid}")),
            )
            n += 1
    return n


# ------------------------------------------------------------------ endpoints


@router.get("/api/labs/info")
def labs_info(request: Request):
    M.data_access(request)
    return {
        "ocr": labparse.ocr_available(),
        "labs": [{"id": k, "name": v} for k, v in labparse.LABS.items()],
        "catalog": sorted(cat.CATALOG.values(), key=lambda a: (a["panel"], a["name"])),
    }


@router.get("/api/patients/{pid}/labs/reports")
def list_reports(pid: str, request: Request):
    master = M.data_access(request)
    M._get_patient(pid, master)
    rows = M.store.conn().execute("SELECT * FROM lab_reports WHERE patient_id=?", (pid,)).fetchall()
    out = [_report_out(r, master) for r in rows]
    out.sort(key=lambda r: (r["status"] != "draft", r.get("collected") or "", r["created_at"]), reverse=False)
    drafts = [r for r in out if r["status"] == "draft"]
    saved = sorted([r for r in out if r["status"] != "draft"], key=lambda r: (r.get("collected") or "", r["created_at"]), reverse=True)
    return drafts + saved


def _parse_upload(sp, filename: str, pid: str, patient: dict, master: bytes) -> dict:
    with sp.open() as fp:
        kind, _mime = media.sniff(fp, filename)
        if kind not in ("pdf", "image"):
            raise M.ApiError(400, "Upload a lab report PDF or a photo of one")
        fp.seek(0)
        data = fp.read(MAX_LAB_FILE + 1)
    if len(data) > MAX_LAB_FILE:
        raise M.ApiError(413, "Lab reports can be up to 50 MB")
    digest = hashlib.sha256(data).hexdigest()
    c = M.store.conn()
    for r in c.execute("SELECT * FROM lab_reports WHERE patient_id=?", (pid,)).fetchall():
        if _report_blob(r, master).get("sha256") == digest:
            out = _report_out(r, master, full=True)
            out["duplicate"] = True
            return out
    warnings: list[str] = []
    try:
        parsed = labparse.parse(data, kind)
    except labparse.ParseError as exc:
        parsed = {"lab": None, "fields": {}, "results": [], "method": None}
        warnings.append(f"{exc}. You can enter the results by hand.")
    except Exception:
        log.exception("lab report parse failed")
        parsed = {"lab": None, "fields": {}, "results": [], "method": None}
        warnings.append("The report could not be read automatically. You can enter the results by hand.")
    del data
    fields = parsed.get("fields", {})
    warnings += parsed.get("warnings", []) + _patient_warnings(patient, fields)
    lab_name = parsed.get("lab_name")
    sid = M._insert_study(
        pid,
        {
            "title": f"{lab_name or 'Lab'} lab report",
            "modality": "LAB",
            "study_date": fields.get("collected"),
            "facility": lab_name,
            "lab_report": True,
        },
        master,
    )
    f = M._ingest(sp, filename, pid, sid, master, "report")
    rid = M.crypto.random_id()
    now = time.time()
    blob = {
        "lab": parsed.get("lab"),
        "lab_name": lab_name,
        "collected": fields.get("collected"),
        "received": fields.get("received"),
        "reported": fields.get("reported"),
        "specimen_id": fields.get("specimen_id"),
        "ordering_provider": fields.get("ordering_provider"),
        "fasting": fields.get("fasting"),
        "file_id": f["id"],
        "study_id": sid,
        "filename": f["filename"],
        "sha256": digest,
        "method": parsed.get("method"),
        "parsed_patient": {k: fields.get(k) for k in ("patient_name", "dob") if fields.get(k)},
        "warnings": warnings,
        "rows": _draft_rows(parsed),
    }
    c.execute(
        "INSERT INTO lab_reports(id,patient_id,status,created_at,updated_at,blob) VALUES(?,?,?,?,?,?)",
        (rid, pid, "draft", now, now, seal(master, blob, f"labreport:{rid}")),
    )
    return _report_out(_report_row(rid), master, full=True)


@router.post("/api/patients/{pid}/labs/upload")
async def upload_report(pid: str, request: Request):
    master = M.data_access(request)
    patient = M._get_patient(pid, master)
    form = await M._upload_form(request)
    try:
        parts = form.files_named("file")
        if len(parts) != 1:
            raise M.ApiError(400, "Upload one lab report at a time")
        p = parts[0]
        if p.size == 0:
            raise M.ApiError(400, f"{M.clean_filename(p.filename)} is empty")
        out = await asyncio.to_thread(_parse_upload, p.spool, p.filename or "lab-report.pdf", pid, patient, master)
    finally:
        form.close()
    if not out.get("duplicate"):
        _activity(request, "lab.upload", patient_id=pid, report_id=out["id"], file_id=out.get("file_id"), lab=out.get("lab"), results=len(out.get("rows", [])))
    return out


@router.post("/api/patients/{pid}/labs/reports")
async def create_report(pid: str, request: Request):
    """A report typed in by hand (no PDF)."""
    master = M.data_access(request)
    M._get_patient(pid, master)
    j = await M.body_json(request, 2 * 1024 * 1024)
    d = _report_fields(j, {"rows": [], "warnings": []})
    rid = M.crypto.random_id()
    now = time.time()
    M.store.conn().execute(
        "INSERT INTO lab_reports(id,patient_id,status,created_at,updated_at,blob) VALUES(?,?,?,?,?,?)",
        (rid, pid, "draft", now, now, seal(master, d, f"labreport:{rid}")),
    )
    _activity(request, "lab.create", patient_id=pid, report_id=rid)
    if j.get("rows") or j.get("save"):
        return await _update(rid, j, master, request)
    return _report_out(_report_row(rid), master, full=True)


@router.get("/api/labs/reports/{rid}")
def get_report(rid: str, request: Request):
    master = M.data_access(request)
    return _report_out(_report_row(rid), master, full=True)


async def _update(rid: str, j: dict, master: bytes, request: Request) -> dict:
    row = _report_row(rid)
    d = _report_fields(j, _report_blob(row, master))
    save = bool(j.get("save"))
    c = M.store.conn()
    rows = None
    if "rows" in j:
        if not isinstance(j["rows"], list) or len(j["rows"]) > MAX_ROWS:
            raise M.ApiError(400, f"Expected a list of up to {MAX_ROWS} results")
        rows = [_clean_row(r, i, d.get("collected")) for i, r in enumerate(j["rows"]) if not (isinstance(r, dict) and r.get("include") is False)]
    status = row["status"]
    if save:
        if rows is None:
            rows = d.get("rows") if status == "draft" else _results_for(rid, master)
            rows = [_clean_row(r, i, d.get("collected")) for i, r in enumerate(rows or [])]
        if not d.get("collected"):
            raise M.ApiError(400, "Enter the date the sample was collected")
        if not rows:
            raise M.ApiError(400, "Add at least one result before saving")
        for r in rows:
            r["date"] = r.get("date") or d["collected"]
        d.pop("rows", None)
        d["warnings"] = []
        c.execute("BEGIN IMMEDIATE")
        try:
            n = _save_results(rid, row["patient_id"], rows, master, j.get("import_previous", True) is not False)
            c.execute("UPDATE lab_reports SET status='saved', updated_at=?, blob=? WHERE id=?", (time.time(), seal(master, d, f"labreport:{rid}"), rid))
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
        # Keep the lab-report study's date and lab in step with the report.
        sid = d.get("study_id")
        srow = c.execute("SELECT * FROM studies WHERE id=?", (sid,)).fetchone() if sid else None
        if srow:
            sd = unseal(master, srow["blob"], f"study:{sid}")
            sd.update(study_date=d.get("collected"), facility=d.get("lab_name") or sd.get("facility"), title=f"{d.get('lab_name') or 'Lab'} lab report")
            c.execute("UPDATE studies SET blob=? WHERE id=?", (seal(master, sd, f"study:{sid}"), sid))
        _activity(request, "lab.save" if status == "draft" else "lab.update", patient_id=row["patient_id"], report_id=rid, results=n)
    else:
        if status == "saved" and rows is not None:
            raise M.ApiError(400, "Send save: true to change the results of a saved report")
        if rows is not None:
            d["rows"] = rows
        c.execute("UPDATE lab_reports SET updated_at=?, blob=? WHERE id=?", (time.time(), seal(master, d, f"labreport:{rid}"), rid))
        if status == "saved":
            _activity(request, "lab.update", patient_id=row["patient_id"], report_id=rid)
    return _report_out(_report_row(rid), master, full=True)


@router.put("/api/labs/reports/{rid}")
async def update_report(rid: str, request: Request):
    master = M.data_access(request)
    j = await M.body_json(request, 2 * 1024 * 1024)
    return await _update(rid, j, master, request)


@router.delete("/api/labs/reports/{rid}")
def delete_report(rid: str, request: Request, keep_file: int = 0):
    master = M.data_access(request)
    row = _report_row(rid)
    d = _report_blob(row, master)
    c = M.store.conn()
    c.execute("DELETE FROM lab_reports WHERE id=?", (rid,))
    removed_file = False
    if not keep_file and d.get("file_id") and _file_exists(d["file_id"]):
        c.execute("DELETE FROM files WHERE id=?", (d["file_id"],))
        M._remove_blobs(d["file_id"])
        removed_file = True
        sid = d.get("study_id")
        if sid and not c.execute("SELECT 1 FROM files WHERE study_id=?", (sid,)).fetchone():
            srow = c.execute("SELECT * FROM studies WHERE id=?", (sid,)).fetchone()
            if srow and unseal(master, srow["blob"], f"study:{sid}").get("lab_report"):
                c.execute("DELETE FROM studies WHERE id=?", (sid,))
    _activity(request, "lab.delete", patient_id=row["patient_id"], report_id=rid, file_id=d.get("file_id") if removed_file else None)
    return {"ok": True}


def _all_results(pid: str, master: bytes) -> list[dict]:
    c = M.store.conn()
    labs = {}
    for r in c.execute("SELECT * FROM lab_reports WHERE patient_id=? AND status='saved'", (pid,)).fetchall():
        b = _report_blob(r, master)
        labs[r["id"]] = b.get("lab_name")
    out = []
    for r in c.execute("SELECT * FROM lab_results WHERE patient_id=?", (pid,)).fetchall():
        if r["report_id"] not in labs:
            continue
        d = _result_blob(r, master)
        d["id"] = r["id"]
        d["report_id"] = r["report_id"]
        d["lab_name"] = labs[r["report_id"]]
        out.append(d)
    # A value copied from a "previous result" column yields to the real one.
    have = {(d["analyte"], d.get("date")) for d in out if d.get("source") != "previous"}
    seen = set()
    uniq = []
    for d in sorted(out, key=lambda d: (d.get("date") or "", d.get("source") == "previous")):
        k = (d["analyte"], d.get("date"))
        if d.get("source") == "previous" and (k in have or k in seen):
            continue
        seen.add(k)
        uniq.append(d)
    return uniq


def _point(d: dict) -> dict:
    return {k: d.get(k) for k in ("id", "report_id", "date", "value", "value_num", "comparator", "unit", "ref_low", "ref_high", "ref_text", "flag", "source", "lab_name", "name")}


@router.get("/api/patients/{pid}/labs/analytes")
def list_analytes(pid: str, request: Request):
    master = M.data_access(request)
    M._get_patient(pid, master)
    groups: dict[str, list[dict]] = {}
    for d in _all_results(pid, master):
        groups.setdefault(d["analyte"], []).append(d)
    out = []
    for key, pts in groups.items():
        pts.sort(key=lambda d: d.get("date") or "")
        last = pts[-1]
        info = cat.info(key) or {}
        out.append({
            "key": key,
            "name": info.get("name") or last.get("name"),
            "loinc": info.get("loinc"),
            "panel": info.get("panel") or last.get("panel") or "Other",
            "unit": last.get("unit"),
            "count": len(pts),
            "latest": _point(last),
            "spark": [[p.get("date"), p.get("value_num")] for p in pts if p.get("value_num") is not None][-24:],
        })
    order = {p: i for i, p in enumerate(["Metabolic", "Liver", "Lipids", "CBC", "Diabetes", "Thyroid", "Vitamins", "Iron", "Inflammation", "Hormones", "Urine", "Other"])}
    out.sort(key=lambda a: (order.get(a["panel"], 99), a["name"].lower()))
    return out


@router.get("/api/patients/{pid}/labs/analytes/{key}")
def analyte_series(pid: str, key: str, request: Request):
    master = M.data_access(request)
    M._get_patient(pid, master)
    pts = sorted((d for d in _all_results(pid, master) if d["analyte"] == key), key=lambda d: d.get("date") or "")
    if not pts:
        raise M.ApiError(404, "No results for this test")
    info = cat.info(key) or {}
    units = sorted({p.get("unit") or "" for p in pts})
    return {
        "key": key,
        "name": info.get("name") or pts[-1].get("name"),
        "loinc": info.get("loinc"),
        "panel": info.get("panel"),
        "units": units,
        "points": [_point(p) for p in pts],
    }


@router.get("/api/patients/{pid}/labs/export.csv")
def export_csv(pid: str, request: Request):
    master = M.data_access(request)
    p = M._get_patient(pid, master)
    b = io.StringIO()
    w = csv.writer(b)
    w.writerow(["date", "test", "loinc", "value", "unit", "flag", "reference_low", "reference_high", "reference_text", "lab", "source"])
    for d in sorted(_all_results(pid, master), key=lambda d: (d.get("date") or "", d.get("name") or "")):
        info = cat.info(d["analyte"]) or {}
        row = [d.get("date"), info.get("name") or d.get("name"), d.get("loinc") or "", d.get("value"), d.get("unit") or "", d.get("flag") or "",
               "" if d.get("ref_low") is None else d["ref_low"], "" if d.get("ref_high") is None else d["ref_high"], d.get("ref_text") or "", d.get("lab_name") or "", d.get("source")]
        w.writerow([("'" + str(x)) if isinstance(x, str) and x[:1] in ("=", "+", "-", "@") and not re.fullmatch(r"-?\d+(\.\d+)?", x) else x for x in row])
    _activity(request, "lab.export", patient_id=pid)
    name = re.sub(r"[^A-Za-z0-9]+", "-", p.get("name") or "patient").strip("-") or "patient"
    return Response(b.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="labs-{name}.csv"'})
