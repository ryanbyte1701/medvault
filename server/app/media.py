"""File type detection, DICOM metadata and preview rendering.

Every function takes a seekable binary file object (usually an encrypted
``Spool``), never a plaintext path, and refuses images whose decoded size
would be unreasonable (decompression bombs).
"""
from __future__ import annotations

import io
import logging
import math
import mimetypes
import os
import zlib
from typing import BinaryIO

log = logging.getLogger("scanvault.media")

PREVIEW_MAX = 1024
# Largest decoded frame we will hold in memory (bytes). 256 MiB covers a
# 16-bit 8k x 8k digital radiograph or mammogram with room to spare.
MAX_FRAME_BYTES = int(os.environ.get("SCANVAULT_MAX_FRAME_MB", "256")) * 1024 * 1024
MAX_IMAGE_PIXELS = 120_000_000
MAX_INFLATED = 256 * 1024 * 1024  # fits a 1 GB container with room for the decode
DEFLATED_TS = "1.2.840.10008.1.2.1.99"


class MediaError(Exception):
    pass


def _head(fp: BinaryIO, n: int) -> bytes:
    fp.seek(0)
    b = fp.read(n)
    fp.seek(0)
    return b


def sniff(fp: BinaryIO, filename: str) -> tuple[str, str]:
    """Return (kind, mime). kind in dicom|image|pdf|zip|other|empty."""
    head = _head(fp, 136)
    name = (filename or "").lower()
    if not head:
        return "empty", "application/octet-stream"
    if len(head) >= 132 and head[128:132] == b"DICM":
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
    if name.endswith((".dcm", ".dicom")) or _looks_like_raw_dicom(fp, head):
        return "dicom", "application/dicom"
    if os.path.basename(name) == "dicomdir":
        return "other", "application/octet-stream"
    mime = mimetypes.guess_type(filename or "")[0] or "application/octet-stream"
    return "other", mime


def _looks_like_raw_dicom(fp: BinaryIO, head: bytes) -> bool:
    """Older CDs store DICOM data sets without the 128-byte preamble and
    without an extension (e.g. IM000003). They start with a group 0002 or
    0008 element; confirm by parsing a few identifying tags."""
    if head[:2] not in (b"\x02\x00", b"\x08\x00"):
        return False
    try:
        import pydicom

        fp.seek(0)
        ds = pydicom.dcmread(fp, force=True, stop_before_pixels=True, specific_tags=["SOPClassUID", "StudyInstanceUID", "Modality"])
        return bool(ds.get("SOPClassUID") or ds.get("StudyInstanceUID"))
    except Exception:
        return False
    finally:
        fp.seek(0)


def _s(v) -> str:
    return str(v).strip() if v not in (None, "") else ""


def _check_deflated(fp: BinaryIO) -> None:
    """A deflated transfer syntax inflates the whole data set in memory.
    Measure the inflated size first, with a hard ceiling."""
    import pydicom

    fp.seek(0)
    try:
        meta = pydicom.filereader.read_preamble(fp, True)  # noqa: F841
        fm = pydicom.filereader._read_file_meta_info(fp)
    except Exception:
        fp.seek(0)
        return
    ts = str(fm.get("TransferSyntaxUID", ""))
    if ts != DEFLATED_TS:
        fp.seek(0)
        return
    d = zlib.decompressobj(-zlib.MAX_WBITS)
    total = 0
    while chunk := fp.read(1 << 20):
        while chunk:
            out = d.decompress(chunk, 1 << 22)
            total += len(out)
            if total > MAX_INFLATED:
                fp.seek(0)
                raise MediaError("Deflated DICOM expands to more than 256 MB")
            chunk = d.unconsumed_tail
    fp.seek(0)


def _dataset(fp: BinaryIO):
    import pydicom

    _check_deflated(fp)
    fp.seek(0)
    ds = pydicom.dcmread(fp, stop_before_pixels=True, force=True)
    fp.seek(0)
    return ds


def dicom_meta(fp: BinaryIO) -> dict:
    try:
        ds = _dataset(fp)
    except Exception as exc:
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
        "series_number": _s(ds.get("SeriesNumber")),
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


def render_preview(fp: BinaryIO, kind: str) -> bytes | None:
    """Return a JPEG preview (or None if not renderable)."""
    try:
        if kind == "image":
            from PIL import Image, ImageOps

            Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
            fp.seek(0)
            im = Image.open(fp)
            if im.width * im.height > MAX_IMAGE_PIXELS:
                raise MediaError("Image is too large to preview")
            im.draft("RGB", (PREVIEW_MAX * 2, PREVIEW_MAX * 2))
            im = ImageOps.exif_transpose(im)
            im.thumbnail((PREVIEW_MAX, PREVIEW_MAX))
            return _jpeg(im)
        if kind == "dicom":
            arr, info = dicom_pixels(fp, None)
            return _preview_from_pixels(arr, info)
    except Exception as exc:
        log.info("No preview: %s", exc)
    return None


def _preview_from_pixels(arr, info: dict) -> bytes:
    import numpy as np
    from PIL import Image

    if info.get("rgb"):
        im = Image.fromarray(arr, "RGB")
    else:
        a = arr.astype("float64")
        lo, hi = (float(x) for x in np.percentile(a, (0.5, 99.5)))
        if hi <= lo:
            lo, hi = float(a.min()), float(a.max())
        if hi <= lo:
            out = np.full(a.shape, 128 if hi else 0, dtype="float64")
        else:
            out = np.clip((a - lo) / (hi - lo), 0, 1) * 255
        if info.get("photometric") == "MONOCHROME1":
            out = 255 - out
        im = Image.fromarray(out.astype("uint8"), "L")
    im.thumbnail((PREVIEW_MAX, PREVIEW_MAX))
    return _jpeg(im)


def _jpeg(im) -> bytes:
    if im.mode not in ("RGB", "L"):
        im = im.convert("RGB")
    buf = io.BytesIO()
    im.save(buf, "JPEG", quality=85)
    return buf.getvalue()


# ------------------------------------------------------------------ window/level rendering

def _frame_bytes(ds) -> int:
    rows, cols = int(ds.get("Rows", 0) or 0), int(ds.get("Columns", 0) or 0)
    spp = int(ds.get("SamplesPerPixel", 1) or 1)
    bits = int(ds.get("BitsAllocated", 16) or 16)
    if rows <= 0 or cols <= 0:
        raise MediaError("DICOM has no image size")
    # Decoding works in at least float32 for grayscale and uint8x3 for colour.
    return rows * cols * spp * max(4 if spp == 1 else 1, math.ceil(bits / 8))


def dicom_pixels(fp: BinaryIO, frame: int | None = None):
    """Decode ONE frame of a DICOM to (array in modality units, info).
    For colour images returns uint8 HxWx3 RGB."""
    import numpy as np
    import pydicom
    from pydicom.pixels import pixel_array

    ds = _dataset(fp)
    if "PixelData" not in ds and "FloatPixelData" not in ds and "DoubleFloatPixelData" not in ds:
        # stop_before_pixels hides the element; check the size tags instead
        pass
    if _frame_bytes(ds) > MAX_FRAME_BYTES:
        raise MediaError("DICOM frame is too large to decode")
    nframes = int(ds.get("NumberOfFrames", 1) or 1)
    if nframes < 1 or nframes > 100_000:
        raise MediaError("Implausible number of frames")
    photometric = str(ds.get("PhotometricInterpretation", "MONOCHROME2"))
    f = nframes // 2 if frame is None else max(0, min(nframes - 1, int(frame)))
    fp.seek(0)
    # pixel_array(index=...) decodes only the requested frame, and converts
    # YBR colour data to RGB itself (as_rgb=True), so we must not convert again.
    arr = pixel_array(fp, index=f if nframes > 1 else None)
    if nframes == 1 and arr.ndim == 4:
        arr = arr[0]
    info = {"frames": nframes, "frame": f, "photometric": photometric, "rgb": False}
    spp = int(ds.get("SamplesPerPixel", 1) or 1)
    if spp == 3 or (arr.ndim == 3 and arr.shape[-1] == 3):
        if arr.dtype != np.uint8:
            mx = float(arr.max()) or 1.0
            arr = np.clip(arr.astype("float32") / mx * 255, 0, 255)
        info["rgb"] = True
        return arr.astype("uint8"), info
    if photometric == "PALETTE COLOR":
        try:
            from pydicom.pixels import apply_color_lut

            rgb = apply_color_lut(arr, ds)
            if rgb.dtype != np.uint8:
                rgb = (rgb.astype("float32") / 257).astype("uint8")
            info["rgb"] = True
            return rgb, info
        except Exception:
            pass
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
        if not (math.isfinite(wc) and math.isfinite(ww)):
            raise ValueError
    except Exception:
        wc = ww = None
    mn, mx = float(arr.min()), float(arr.max())
    if not ww or ww <= 1:
        lo, hi = (float(x) for x in np.percentile(arr, (0.5, 99.5)))
        if hi <= lo:
            lo, hi = mn, mx
        if hi <= lo:  # uniform frame: centre the window on its value
            lo, hi = lo - 1, hi + 1
        wc, ww = (lo + hi) / 2, hi - lo
    info.update(
        default_center=round(wc, 2),
        default_width=round(ww, 2),
        min=mn,
        max=mx,
        modality=str(ds.get("Modality", "")),
        burned_in=str(ds.get("BurnedInAnnotation", "")).strip().upper(),
    )
    return arr, info


def render_window(arr, info: dict, center: float | None, width: float | None, invert: bool = False, max_size: int = 2048) -> tuple[bytes, float | None, float | None]:
    """Returns (jpeg, center used, width used)."""
    import numpy as np
    from PIL import Image

    c = w = None
    if info.get("rgb"):
        im = Image.fromarray(arr, "RGB")
        if invert:
            from PIL import ImageOps

            im = ImageOps.invert(im)
    else:
        c = info["default_center"] if center is None else center
        w = info["default_width"] if width is None else width
        w = max(1.0, w)
        if w <= 1.0:
            # DICOM PS3.3 C.11.2.1.2: width 1 is a threshold at the centre
            out = np.where(arr < c - 0.5, 0.0, 255.0)
        else:
            out = np.clip(((arr - (c - 0.5)) / (w - 1) + 0.5), 0, 1) * 255
        if (info.get("photometric") == "MONOCHROME1") != bool(invert):
            out = 255 - out
        im = Image.fromarray(out.astype("uint8"), "L")
    im.thumbnail((max_size, max_size))
    return _jpeg(im), c, w
