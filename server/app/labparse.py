"""Read lab results out of a lab report PDF (or a photo of one).

Everything runs locally. Text PDFs are read with pdfplumber (word positions);
scanned PDFs and photos go through Tesseract OCR when it is installed. The
plaintext never touches the disk: pages are handed to Tesseract on stdin.

The parser looks for the results table header that Labcorp ("Tests  Result
Flag  Units  Reference Interval", or the newer "Current Result and Flag /
Previous Result and Date") and Quest / Sonora Quest ("Test Name  In Range
Out Of Range  Reference Range  Lab") print, and splits each row into columns
by position. Without a recognizable header it falls back to reading each row
left to right. Whatever it finds is a draft: the user reviews it before any
value is saved.
"""
from __future__ import annotations

import io
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import date

from . import labcatalog as cat

MAX_PAGES = 30
OCR_DPI = 300
OCR_TIMEOUT = 120

LABS = {
    "labcorp": "Labcorp",
    "sonora_quest": "Sonora Quest Laboratories",
    "quest": "Quest Diagnostics",
}


class ParseError(Exception):
    pass


@dataclass
class Word:
    text: str
    x0: float
    x1: float
    top: float
    bottom: float

    @property
    def h(self) -> float:
        return max(1.0, self.bottom - self.top)


# ------------------------------------------------------------------ extraction


def _pdf_words(data: bytes) -> list[list[Word]]:
    import pdfplumber

    pages: list[list[Word]] = []
    try:
        with pdfplumber.open(io.BytesIO(data)) as pdf:
            for page in pdf.pages[:MAX_PAGES]:
                ws = page.extract_words(x_tolerance=1.5, y_tolerance=2.5, keep_blank_chars=False)
                pages.append([Word(w["text"], float(w["x0"]), float(w["x1"]), float(w["top"]), float(w["bottom"])) for w in ws if w["text"].strip()])
    except Exception as exc:  # pdfminer raises many types on damaged files
        raise ParseError("This PDF could not be read") from exc
    return pages


def ocr_available() -> bool:
    return shutil.which("tesseract") is not None


def _tesseract(png: bytes, scale: float) -> list[Word]:
    exe = shutil.which("tesseract")
    if not exe:
        raise ParseError("OCR is not installed")
    try:
        r = subprocess.run([exe, "stdin", "stdout", "--psm", "6", "-l", "eng", "tsv"], input=png, capture_output=True, timeout=OCR_TIMEOUT, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ParseError("OCR took too long") from exc
    if r.returncode != 0:
        raise ParseError("OCR failed")
    out: list[Word] = []
    for line in r.stdout.decode("utf-8", "replace").splitlines()[1:]:
        f = line.split("\t")
        if len(f) < 12 or f[0] != "5" or not f[11].strip():
            continue
        try:
            conf = float(f[10])
            left, top, w, h = (int(x) for x in f[6:10])
        except ValueError:
            continue
        if conf < 0:
            continue
        out.append(Word(f[11].strip(), left / scale, (left + w) / scale, top / scale, (top + h) / scale))
    return out


def _png(img) -> bytes:
    b = io.BytesIO()
    img.convert("L").save(b, "PNG")
    return b.getvalue()


def _ocr_pdf(data: bytes) -> list[list[Word]]:
    import pypdfium2 as pdfium

    scale = OCR_DPI / 72
    pages = []
    doc = pdfium.PdfDocument(data)
    try:
        for i in range(min(len(doc), MAX_PAGES)):
            img = doc[i].render(scale=scale).to_pil()
            pages.append(_tesseract(_png(img), scale))
    finally:
        doc.close()
    return pages


def _ocr_image(data: bytes) -> list[list[Word]]:
    from PIL import Image, ImageOps

    try:
        img = ImageOps.exif_transpose(Image.open(io.BytesIO(data)))
    except Exception as exc:
        raise ParseError("This image could not be read") from exc
    if max(img.size) < 1600:  # small photos OCR better upscaled
        k = 1600 / max(img.size)
        img = img.resize((int(img.width * k), int(img.height * k)))
    return [_tesseract(_png(img), 300 / 72)]


def extract(data: bytes, kind: str) -> tuple[list[list[Word]], str]:
    """Words per page and the method used ("text" or "ocr")."""
    if kind == "image":
        if not ocr_available():
            raise ParseError("Reading photos needs OCR, which is not installed on this server")
        return _ocr_image(data), "ocr"
    pages = _pdf_words(data)
    chars = sum(len(w.text) for p in pages for w in p)
    if chars >= 80:
        return pages, "text"
    if not ocr_available():
        raise ParseError("This PDF has no text layer (it is a scan) and OCR is not installed on this server")
    return _ocr_pdf(data), "ocr"


# ------------------------------------------------------------------ layout


def lines_of(words: list[Word]) -> list[list[Word]]:
    if not words:
        return []
    hs = sorted(w.h for w in words)
    tol = max(2.0, hs[len(hs) // 2] * 0.55)
    ws = sorted(words, key=lambda w: ((w.top + w.bottom) / 2, w.x0))
    lines: list[list[Word]] = []
    cur: list[Word] = []
    cy = None
    for w in ws:
        y = (w.top + w.bottom) / 2
        if cur and abs(y - cy) > tol:
            lines.append(sorted(cur, key=lambda w: w.x0))
            cur = []
        if not cur:
            cy = y
        cur.append(w)
    if cur:
        lines.append(sorted(cur, key=lambda w: w.x0))
    return lines


def cells_of(line: list[Word]) -> list[tuple[float, str]]:
    """Split a line into cells where the gap between words is wide."""
    cells: list[list[Word]] = []
    for w in line:
        if cells:
            prev = cells[-1][-1]
            if w.x0 - prev.x1 < max(3.5, 0.75 * min(w.h, prev.h)):
                cells[-1].append(w)
                continue
        cells.append([w])
    return [(c[0].x0, " ".join(w.text for w in c)) for c in cells]


_HEADER_PATTERNS = [
    ("result", "current result and flag"),
    ("prev", "previous result and date"),
    ("name", "test name"),
    ("result", "in range"),
    ("outrange", "out of range"),
    ("ref", "reference interval"),
    ("ref", "reference range"),
    ("ref", "ref range"),
    ("name", "tests"),
    ("name", "test"),
    ("result", "result"),
    ("result", "value"),
    ("flag", "flag"),
    ("units", "units"),
    ("units", "unit"),
    ("lab", "lab"),
]


def header_columns(line: list[Word]) -> list[tuple[str, float]] | None:
    toks = [re.sub(r"[^a-z]", "", w.text.lower()) for w in line]
    used = [False] * len(toks)
    found: dict[str, float] = {}
    for col, phrase in _HEADER_PATTERNS:
        p = phrase.split()
        for i in range(len(toks) - len(p) + 1):
            if any(used[i : i + len(p)]) or toks[i : i + len(p)] != p:
                continue
            if col not in found:
                found[col] = line[i].x0
            for j in range(i, i + len(p)):
                used[j] = True
            break
    if "name" not in found or "result" not in found or not ({"ref", "units", "outrange"} & found.keys()):
        return None
    if sum(used) < len(toks) * 0.6:  # mostly other words: a sentence, not a header
        return None
    return sorted(found.items(), key=lambda kv: kv[1])


def _columnize(line: list[Word], cols: list[tuple[str, float]]) -> dict[str, str]:
    bounds = []
    for i, (name, x) in enumerate(cols):
        if i == 0:
            bounds.append((name, -1e9))
        else:
            gap = x - cols[i - 1][1]
            bounds.append((name, x - min(15.0, gap * 0.3)))
    out: dict[str, list[str]] = {}
    for w in line:
        col = bounds[0][0]
        for name, b in bounds:
            if w.x0 >= b:
                col = name
        out.setdefault(col, []).append(w.text)
    return {k: " ".join(v) for k, v in out.items()}


# ------------------------------------------------------------------ values

DATE_RE = re.compile(r"\b(\d{1,2})/(\d{1,2})/(\d{2}|\d{4})\b")
NUM_RE = re.compile(r"^(<=|>=|<|>|≤|≥)?\s*(-?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?|-?\.\d+)$")
QUALITATIVE = (
    "non reactive", "nonreactive", "not detected", "none seen", "negative", "positive", "reactive", "detected",
    "normal", "abnormal", "equivocal", "indeterminate", "trace", "clear", "cloudy", "yellow", "straw", "amber",
    "pending", "see note", "see below", "tnp", "dnr", "qns",
)
UNIT_RE = re.compile(
    r"^(%|fl|pg|ratio|index|seconds|sec|mm/hr|mmhg|ph|"
    r"(x ?10e?\d+|x10\^?\d+|thousand|million|10\*\d+|10\^\d+)\/?[a-zµ]*l?|"
    r"[a-zµ]{0,4}(iu|u|g|mol|eq|osm|cells|copies|units?|kat)?/[a-z0-9µ.]+(/[0-9.]+m2)?|"
    r"mg|g|ng|ug|mcg|meq|mmol|umol|nmol|pmol)$",
    re.I,
)
_LAB_CODE_RE = re.compile(r"^(0\d|[A-Z]{2,3})$")
_NOISE_NAMES = re.compile(
    r"^(page|patient|specimen|date|dob|account|acct|physician|ordering|ordered|phone|control|report|final|"
    r"collected|received|reported|age|sex|gender|requisition|client|fax|address|npi|status|lab ?director|"
    r"director|ph:|tel|time|comment|note|please|for inquiries|copyright|©|labcorp|quest|sonora|"
    r"performing|this test|reference|test name|tests?$|in range|out of range|result|flag|units?)\b",
    re.I,
)


def iso_date(s: str | None) -> str | None:
    if not s:
        return None
    m = DATE_RE.search(s)
    if not m:
        m2 = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", s)
        if not m2:
            return None
        y, mo, d = (int(x) for x in m2.groups())
    else:
        mo, d, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if y < 100:
            y += 2000 if y < 70 else 1900
    try:
        return date(y, mo, d).isoformat()
    except ValueError:
        return None


def parse_number(s: str) -> tuple[str | None, float | None]:
    s = s.strip().replace(" ", "")
    m = NUM_RE.match(s)
    if not m:
        return None, None
    comp = {"≤": "<=", "≥": ">="}.get(m.group(1), m.group(1))
    try:
        return comp, float(m.group(2).replace(",", ""))
    except ValueError:
        return None, None


def parse_value(text: str) -> dict | None:
    """'5.9 High', '108 H', '<0.5', 'Negative', '>60' -> value, flag."""
    t = (text or "").strip().strip("*")
    if not t:
        return None
    toks = t.split()
    flag = None
    while len(toks) > 1 and cat.parse_flag(toks[-1]):
        flag = cat.parse_flag(toks.pop())
    if len(toks) >= 2 and toks[0] in ("<", ">", "<=", ">="):
        toks = [toks[0] + toks[1]] + toks[2:]
    if len(toks) == 1 and not flag:
        m = re.match(r"^(.*\d)(HH|LL|H|L|A)$", toks[0])  # OCR or tight layouts glue the flag on: "221H"
        if m and parse_number(m.group(1))[1] is not None:
            toks, flag = [m.group(1)], cat.parse_flag(m.group(2))
    joined = " ".join(toks)
    comp, num = parse_number(toks[0]) if toks else (None, None)
    if num is not None and len(toks) == 1:
        return {"value": toks[0], "num": num, "comparator": comp, "flag": flag}
    low = joined.lower().rstrip(".")
    for q in QUALITATIVE:
        if low == q or low.startswith(q + " "):
            return {"value": joined[: len(q)] if low == q else joined, "num": None, "comparator": None, "flag": flag}
    return None


def parse_ref(text: str) -> dict | None:
    t = (text or "").strip()
    if not t:
        return None
    t = re.sub(r"<\s*or\s*=\s*", "<=", t, flags=re.I)
    t = re.sub(r">\s*or\s*=\s*", ">=", t, flags=re.I)
    t = t.replace("≤", "<=").replace("≥", ">=").replace("–", "-")
    m = re.match(r"^(-?\d*\.?\d+)\s*-\s*(-?\d*\.?\d+)(?:\s+(.*))?$", t)
    if m:
        lo, hi = float(m.group(1)), float(m.group(2))
        if lo <= hi:
            return {"low": lo, "high": hi, "text": f"{m.group(1)}-{m.group(2)}", "rest": (m.group(3) or "").strip()}
    m = re.match(r"^(<=|>=|<|>)\s*(-?\d*\.?\d+)(?:\s+(.*))?$", t)
    if m:
        op, v = m.group(1), float(m.group(2))
        out = {"low": None, "high": None, "text": f"{op}{m.group(2)}", "rest": (m.group(3) or "").strip()}
        out["high" if op.startswith("<") else "low"] = v
        return out
    low = t.lower()
    for q in ("not estab.", "not estab", "negative", "non reactive", "nonreactive", "not detected", "none seen", "normal", "neg"):
        if low.startswith(q):
            return {"low": None, "high": None, "text": t[: len(q)], "rest": t[len(q):].strip()}
    return None


def is_unit(s: str) -> bool:
    s = s.strip().replace(" ", "")
    return bool(s) and bool(UNIT_RE.match(s)) and not DATE_RE.search(s)


def _derive_flag(r: dict) -> str | None:
    n = r.get("value_num")
    if n is None:
        return None
    lo, hi = r.get("ref_low"), r.get("ref_high")
    if hi is not None and n > hi:
        return "H"
    if lo is not None and n < lo:
        return "L"
    return None


# ------------------------------------------------------------------ rows


def _clean_name(name: str) -> tuple[str, str | None]:
    name = name.strip(" .:*")
    code = None
    m = re.match(r"^(.*?)\s+(0\d)$", name)
    if m:
        name, code = m.group(1), m.group(2)
    name = re.sub(r"[¹²³⁰-⁹]+$", "", name).strip(" ,")
    return name, code


def _good_name(name: str) -> bool:
    letters = sum(ch.isalpha() for ch in name)
    return letters >= 2 and len(name) <= 80 and len(name.split()) <= 7 and not _NOISE_NAMES.match(name) and not DATE_RE.search(name)


def _row_from_columns(c: dict[str, str]) -> dict | None:
    if sum(len(v.split()) for v in c.values()) > 16:
        return None  # a sentence (comment or footnote), not a result row
    name, code = _clean_name(c.get("name", ""))
    if not _good_name(name):
        return None
    val = parse_value(c.get("result", "")) or parse_value(c.get("outrange", ""))
    if val is None:
        # Value printed a little left of its column, glued to the name.
        m = re.match(r"^(.*?[A-Za-z)%].*?)\s+(0\d\s+)?([<>]?=?\s*-?\d[\d,]*\.?\d*)$", name)
        if m and not c.get("result") and not c.get("outrange"):
            name, code = m.group(1), (m.group(2) or "").strip() or code
            val = parse_value(m.group(3))
    if val is None:
        return None
    r = {"name": name, "value": val["value"], "value_num": val["num"], "comparator": val["comparator"], "flag": val["flag"], "lab_code": code}
    if c.get("outrange") and not c.get("result") and not r["flag"]:
        r["flag"] = "A"
    if c.get("flag"):
        r["flag"] = cat.parse_flag(c["flag"].split()[0]) or r["flag"]
    units = (c.get("units") or "").strip()
    ref = parse_ref(c.get("ref", ""))
    if ref:
        r.update(ref_low=ref["low"], ref_high=ref["high"], ref_text=ref["text"])
        rest = ref["rest"].split()
        if rest and not units and is_unit(rest[0]):
            units = rest[0]
            rest = rest[1:]
        if rest and _LAB_CODE_RE.match(rest[-1]) and not r["lab_code"]:
            r["lab_code"] = rest[-1]
    elif c.get("ref"):
        rt = c["ref"].strip().split()
        if rt and not units and is_unit(rt[0]):
            units = rt.pop(0)
        if rt and _LAB_CODE_RE.match(rt[-1]) and not r["lab_code"]:
            r["lab_code"] = rt.pop()
        note = " ".join(rt)
        if note and note.lower() not in ("(calc)", "calc"):
            r["ref_text"] = note
    if units:
        r["unit"] = units
    if c.get("lab") and not r.get("lab_code"):
        r["lab_code"] = c["lab"].split()[0]
    if c.get("prev"):
        _add_prev(r, c["prev"])
    return r


def _add_prev(r: dict, text: str) -> None:
    d = iso_date(text)
    before = DATE_RE.split(text)[0].strip() if DATE_RE.search(text) else text.strip()
    v = parse_value(before)
    if d and v:
        r["prev_value"], r["prev_num"], r["prev_date"] = v["value"], v["num"], d


def _row_from_cells(cells: list[str]) -> dict | None:
    """No header: name first, then the value, then flag/units/reference."""
    toks: list[str] = []
    for c in cells:
        toks.append(c)
    if len(toks) < 2:
        # One wide cell: split it on single spaces as a last resort.
        parts = toks[0].split() if toks else []
        if len(parts) > 12:
            return None
        idx = next((i for i, p in enumerate(parts) if i > 0 and parse_value(p) and not _LAB_CODE_RE.match(p) or (i > 0 and parts[i - 1] in ("<", ">"))), None)
        if idx is None:
            return None
        toks = [" ".join(parts[:idx])] + parts[idx:]
    name, code = _clean_name(toks[0])
    i = 1
    while i < len(toks) and _LAB_CODE_RE.match(toks[i].strip()) and i + 1 < len(toks):
        code = toks[i].strip()
        i += 1
    if not _good_name(name) or i >= len(toks):
        return None
    head = toks[i].split()
    val = parse_value(toks[i])
    rest_tokens: list[str] = []
    if val is None and head:
        val = parse_value(head[0])
        if val is not None:
            rest_tokens = head[1:]
    if val is None:
        return None
    r = {"name": name, "value": val["value"], "value_num": val["num"], "comparator": val["comparator"], "flag": val["flag"], "lab_code": code}
    rest = rest_tokens + [t for c in toks[i + 1:] for t in [c]]
    j = 0
    pending_prev = None
    while j < len(rest):
        t = rest[j].strip()
        f = cat.parse_flag(t)
        if f and not r["flag"]:
            r["flag"] = f
        elif DATE_RE.search(t):
            if pending_prev is not None:
                r["prev_value"], r["prev_num"], r["prev_date"] = pending_prev["value"], pending_prev["num"], iso_date(t)
                pending_prev = None
            elif parse_value(DATE_RE.split(t)[0].strip() or "x"):
                _add_prev(r, t)
        elif "ref_text" not in r and parse_ref(t) and not (parse_value(t) and j + 1 < len(rest) and DATE_RE.search(rest[j + 1])):
            ref = parse_ref(t)
            r.update(ref_low=ref["low"], ref_high=ref["high"], ref_text=ref["text"])
            for x in ref["rest"].split():
                if is_unit(x) and "unit" not in r:
                    r["unit"] = x
                elif _LAB_CODE_RE.match(x):
                    r["lab_code"] = x
        elif is_unit(t) and "unit" not in r:
            r["unit"] = t
        elif parse_value(t) and "ref_text" not in r and pending_prev is None:
            pending_prev = parse_value(t)
        elif _LAB_CODE_RE.match(t):
            r["lab_code"] = r["lab_code"] or t
        j += 1
    if not any(k in r for k in ("unit", "ref_text")) and not r["flag"] and not cat.lookup(name):
        return None  # a stray "something 12" line, not a result
    return r


# ------------------------------------------------------------------ report


def detect_lab(text: str) -> str | None:
    t = text.lower()
    if "sonora quest" in t or "sonoraquest" in t:
        return "sonora_quest"
    if "labcorp" in t or "laboratory corporation of america" in t:
        return "labcorp"
    if "quest diagnostics" in t or "questdiagnostics" in t:
        return "quest"
    return None


def _field(text: str, labels: str, value: str, strict: bool = True) -> str | None:
    sep = r"[ \t]*[:#][ \t]*(?:\|[ \t]*)?" if strict else r"[ \t]*[:#|]?[ \t]*"
    m = re.search(rf"\b(?:{labels}){sep}{value}", text, re.I)
    return m.group(1).strip() if m else None


_DATE_V = r"(\d{1,2}/\d{1,2}/\d{2,4})"
_TEXT_V = r"([^|\n]{2,60})"


def header_fields(cell_text: str) -> dict:
    t = cell_text
    out = {
        "collected": iso_date(_field(t, r"date\s+collected|collection\s+date|date\s+of\s+collection|collected(?:\s+date)?", _DATE_V, False)),
        "received": iso_date(_field(t, r"date\s+received|received(?:\s+date)?", _DATE_V, False)),
        "reported": iso_date(_field(t, r"date\s+reported|report\s+date|reported(?:\s+date)?", _DATE_V, False)),
        "dob": iso_date(_field(t, r"dob|d\.o\.b\.|date\s+of\s+birth|birth\s*date", _DATE_V, False)),
        "specimen_id": _field(t, r"specimen\s+id|specimen\s+number|specimen|accession(?:\s+number|\s+#)?", r"([A-Z0-9][A-Z0-9-]{4,24})"),
        "ordering_provider": _field(t, r"ordering\s+physician|ordering\s+provider|ordering\s+md|physician\s+name|physician|provider", _TEXT_V),
        "patient_name": _field(t, r"patient\s+name|patient", r"([A-Z][A-Za-z'\-]+,\s*[A-Z][A-Za-z'\- .]{1,40}|[A-Z][A-Za-z'\-]+\s+[A-Z][A-Za-z'\-]+(?:\s+[A-Z][A-Za-z'\-]+)?)"),
        "fasting": _field(t, r"fasting", r"(yes|no|y|n)\b"),
    }
    for k in ("ordering_provider", "patient_name"):
        if out[k]:
            out[k] = re.split(r"\s{2,}|\s+(?:dob|age|sex|gender|phone|npi|id|acct)\b", out[k], flags=re.I)[0].strip(" ,:")
            if _NOISE_NAMES.match(out[k] + " ") and k == "patient_name":
                out[k] = None
    return {k: v for k, v in out.items() if v}


def parse_pages(pages: list[list[Word]]) -> dict:
    results: list[dict] = []
    all_cells: list[str] = []
    cols = None
    panel = None
    for pno, words in enumerate(pages, start=1):
        for line in lines_of(words):
            cells = cells_of(line)
            all_cells.append(" | ".join(c for _, c in cells))
            hc = header_columns(line)
            if hc:
                cols = hc
                continue
            row = None
            if cols:
                row = _row_from_columns(_columnize(line, cols))
            if row is None:
                row = _row_from_cells([c for _, c in cells])
            if row is None:
                if len(cells) == 1 and 3 <= len(cells[0][1]) <= 60 and ":" not in cells[0][1] and _good_name(cells[0][1]) and not parse_value(cells[0][1].split()[-1]):
                    panel = cells[0][1].strip(" :")
                continue
            row["page"] = pno
            if panel:
                row["panel"] = panel
            results.append(row)
    text = "\n".join(all_cells)
    lab = detect_lab(text)
    fields = header_fields(text)
    if "patient_name" not in fields:
        # Quest prints the name, unlabeled, under a "Patient Information" heading.
        for i, ln in enumerate(all_cells[:-1]):
            if ln.lower().startswith("patient information"):
                m = re.match(r"^([A-Z][A-Za-z'\-]+,\s*[A-Z][A-Za-z'\- .]{1,40})(?:\s*\||$)", all_cells[i + 1])
                if m:
                    fields["patient_name"] = m.group(1).strip()
                break
    for r in results:
        key = cat.lookup(r["name"])
        r["analyte"] = key or cat.slug(r["name"])
        r["catalog"] = bool(key)
        if key:
            r["loinc"] = cat.info(key)["loinc"]
        if not r.get("flag"):
            r["flag"] = _derive_flag(r)
            r["flag_derived"] = bool(r["flag"])
        r["confidence"] = "high" if key and (r.get("unit") or r.get("ref_text")) else "medium" if (r.get("unit") or r.get("ref_text") or key) else "low"
    # The same result can appear twice (a summary page that repeats
    # out-of-range values, as Quest prints): keep the first of each.
    seen = set()
    uniq = []
    for r in results:
        k = (r["analyte"], r["value"], r.get("unit"))
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)
    return {"lab": lab, "lab_name": LABS.get(lab or "", None), "fields": fields, "results": uniq, "table_header": bool(cols)}


def parse(data: bytes, kind: str = "pdf") -> dict:
    pages, method = extract(data, kind)
    out = parse_pages(pages)
    out["method"] = method
    out["pages"] = len(pages)
    warnings = []
    if not out["results"]:
        warnings.append("No results were recognized. You can add them by hand.")
    if method == "ocr":
        warnings.append("This report was read with OCR. Check every value against the PDF.")
    if out["lab"] is None:
        warnings.append("The lab was not recognized; results were read with the generic layout.")
    out["warnings"] = warnings
    return out
