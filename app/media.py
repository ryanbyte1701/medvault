"""File type detection, DICOM metadata and preview rendering."""
from __future__ import annotations

import io
import logging
import mimetypes
from pathlib import Path

log = logging.getLogger("scanvault.media")

PREVIEW_MAX = 1024


def sniff(path: Path, filename: str) -> tuple[str, str]:
    """Return (kind, mime). kind in dicom|image|pdf|zip|other."""
    with open(path, "rb") as f:
        head = f.read(136)
    name = filename.lower()
    if len(head) >= 132 and head[128:132] == b"DICM":
        return "dicom", "application/dicom"
    if name.endswith((".dcm", ".dicom")):
        return "dicom", "application/dicom"
    if head.startswith(b"%PDF"):
        return "pdf", "application/pdf"
    if head.startswith(b"PK\x03\x04"):
        return "zip", "application/zip"
    if head.startswith(b"\x89PNG"):
        return "image", "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image", "image/jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image", "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image", "image/webp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "image", "image/tiff"
    if head[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1"):
        return "image", "image/heic"
    if name == "dicomdir":
        return "other", "application/octet-stream"
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return "other", mime


def _s(v) -> str:
    return str(v).strip() if v not in (None, "") else ""


def dicom_meta(path: Path) -> dict:
    try:
        import pydicom

        ds = pydicom.dcmread(str(path), stop_before_pixels=True, force=True)
    except Exception as exc:  # pragma: no cover
        log.warning("DICOM parse failed: %s", exc)
        return {}
    pn = ds.get("PatientName")
    return {
        "patient_name": _s(pn).replace("^", " ").strip() if pn else "",
        "patient_id": _s(ds.get("PatientID")),
        "birth_date": _fmt_date(_s(ds.get("PatientBirthDate"))),
        "sex": _s(ds.get("PatientSex")),
        "study_uid": _s(ds.get("StudyInstanceUID")),
        "series_uid": _s(ds.get("SeriesInstanceUID")),
        "study_date": _fmt_date(_s(ds.get("StudyDate"))),
        "study_description": _s(ds.get("StudyDescription")),
        "series_description": _s(ds.get("SeriesDescription")),
        "modality": _s(ds.get("Modality")),
        "body_part": _s(ds.get("BodyPartExamined")),
        "institution": _s(ds.get("InstitutionName")),
        "referring_physician": _s(ds.get("ReferringPhysicianName")).replace("^", " "),
        "accession": _s(ds.get("AccessionNumber")),
        "instance_number": _s(ds.get("InstanceNumber")),
        "rows": _s(ds.get("Rows")),
        "columns": _s(ds.get("Columns")),
        "frames": _s(ds.get("NumberOfFrames")) or "1",
        "transfer_syntax": _s(getattr(getattr(ds, "file_meta", None), "TransferSyntaxUID", "")),
    }


def _fmt_date(d: str) -> str:
    if len(d) == 8 and d.isdigit():
        return f"{d[:4]}-{d[4:6]}-{d[6:]}"
    return d


def render_preview(path: Path, kind: str) -> bytes | None:
    """Return a JPEG preview (or None if not renderable)."""
    try:
        from PIL import Image, ImageOps

        if kind == "image":
            im = Image.open(path)
            im = ImageOps.exif_transpose(im)
            im.thumbnail((PREVIEW_MAX, PREVIEW_MAX))
            return _jpeg(im)
        if kind == "dicom":
            return _render_dicom(path)
    except Exception as exc:
        log.info("No preview for %s: %s", path.name, exc)
    return None


def _render_dicom(path: Path) -> bytes | None:
    import numpy as np
    import pydicom
    from PIL import Image

    ds = pydicom.dcmread(str(path), force=True)
    arr = ds.pixel_array
    nframes = int(ds.get("NumberOfFrames", 1) or 1)
    photometric = str(ds.get("PhotometricInterpretation", "MONOCHROME2"))
    if nframes > 1:
        arr = arr[nframes // 2]
    if photometric in ("RGB", "YBR_FULL", "YBR_FULL_422") or (arr.ndim == 3 and arr.shape[-1] == 3):
        if photometric.startswith("YBR"):
            from pydicom.pixels import convert_color_space

            arr = convert_color_space(arr, photometric, "RGB")
        im = Image.fromarray(arr.astype("uint8"), "RGB")
    else:
        try:
            from pydicom.pixels import apply_modality_lut, apply_voi_lut

            arr = apply_modality_lut(arr, ds)
            arr = apply_voi_lut(arr, ds)
        except Exception:
            pass
        arr = arr.astype("float64")
        lo, hi = np.percentile(arr, (0.5, 99.5))
        if hi <= lo:
            lo, hi = float(arr.min()), float(arr.max()) or 1.0
        arr = np.clip((arr - lo) / (hi - lo), 0, 1) * 255
        if photometric == "MONOCHROME1":
            arr = 255 - arr
        im = Image.fromarray(arr.astype("uint8"), "L")
    im.thumbnail((PREVIEW_MAX, PREVIEW_MAX))
    return _jpeg(im)


def _jpeg(im) -> bytes:
    if im.mode not in ("RGB", "L"):
        im = im.convert("RGB")
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=85)
    return buf.getvalue()


# ------------------------------------------------------------------ window/level rendering

def dicom_pixels(path: Path, frame: int | None = None):
    """Decode a DICOM to (array in modality units, info). For RGB returns uint8 HxWx3."""
    import numpy as np
    import pydicom

    ds = pydicom.dcmread(str(path), force=True)
    arr = ds.pixel_array
    nframes = int(ds.get("NumberOfFrames", 1) or 1)
    photometric = str(ds.get("PhotometricInterpretation", "MONOCHROME2"))
    info = {"frames": nframes, "photometric": photometric, "rgb": False}
    if nframes > 1:
        f = nframes // 2 if frame is None else max(0, min(nframes - 1, frame))
        arr = arr[f]
        info["frame"] = f
    if photometric in ("RGB", "YBR_FULL", "YBR_FULL_422") or (arr.ndim == 3 and arr.shape[-1] == 3):
        if photometric.startswith("YBR"):
            from pydicom.pixels import convert_color_space

            arr = convert_color_space(arr, photometric, "RGB")
        info["rgb"] = True
        return arr.astype("uint8"), info
    try:
        from pydicom.pixels import apply_modality_lut

        arr = apply_modality_lut(arr, ds)
    except Exception:
        pass
    arr = arr.astype("float32")
    wc, ww = ds.get("WindowCenter"), ds.get("WindowWidth")
    try:
        wc = float(wc[0] if isinstance(wc, (list, pydicom.multival.MultiValue)) else wc)
        ww = float(ww[0] if isinstance(ww, (list, pydicom.multival.MultiValue)) else ww)
    except Exception:
        wc = ww = None
    if not ww or ww <= 1:
        lo, hi = (float(x) for x in np.percentile(arr, (0.5, 99.5)))
        if hi <= lo:
            lo, hi = float(arr.min()), float(arr.max()) + 1
        wc, ww = (lo + hi) / 2, hi - lo
    info.update(
        default_center=round(wc, 2),
        default_width=round(ww, 2),
        min=float(arr.min()),
        max=float(arr.max()),
        modality=str(ds.get("Modality", "")),
    )
    return arr, info


def render_window(arr, info: dict, center: float | None, width: float | None, invert: bool = False, max_size: int = 2048) -> bytes:
    import numpy as np
    from PIL import Image

    if info.get("rgb"):
        im = Image.fromarray(arr, "RGB")
        if invert:
            from PIL import ImageOps

            im = ImageOps.invert(im)
    else:
        c = info["default_center"] if center is None else center
        w = max(1.0, info["default_width"] if width is None else width)
        # DICOM PS3.3 C.11.2.1.2 linear VOI function
        out = np.clip(((arr - (c - 0.5)) / (w - 1) + 0.5), 0, 1) * 255
        if (info.get("photometric") == "MONOCHROME1") != bool(invert):
            out = 255 - out
        im = Image.fromarray(out.astype("uint8"), "L")
    im.thumbnail((max_size, max_size))
    return _jpeg(im)
