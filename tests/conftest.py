import io
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_DATA = tempfile.mkdtemp(prefix="sv-test-")
os.environ["SCANVAULT_DATA"] = _DATA


def make_dicom(path: Path, study_uid: str = "1.2.3.4.5", instance: int = 1, modality: str = "MR"):
    import numpy as np
    from pydicom.dataset import FileDataset, FileMetaDataset
    from pydicom.uid import ExplicitVRLittleEndian, generate_uid, SecondaryCaptureImageStorage

    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = SecondaryCaptureImageStorage
    meta.MediaStorageSOPInstanceUID = generate_uid()
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds = FileDataset(str(path), {}, file_meta=meta, preamble=b"\0" * 128)
    ds.SOPClassUID = meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = meta.MediaStorageSOPInstanceUID
    ds.PatientName = "DOE^JANE"
    ds.PatientID = "MRN123"
    ds.StudyInstanceUID = study_uid
    ds.SeriesInstanceUID = study_uid + ".1"
    ds.StudyDate = "20260314"
    ds.Modality = modality
    ds.StudyDescription = "KNEE LT W/O CONTRAST"
    ds.SeriesDescription = "SAG PD FS"
    ds.InstitutionName = "Lakeside Imaging"
    ds.InstanceNumber = instance
    ds.Rows, ds.Columns = 64, 64
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated, ds.BitsStored, ds.HighBit, ds.PixelRepresentation = 16, 12, 11, 0
    yy, xx = np.mgrid[0:64, 0:64]
    ds.PixelData = (((xx - 32) ** 2 + (yy - 32) ** 2 < 400) * 3000 + instance * 10).astype("uint16").tobytes()
    ds.save_as(str(path), enforce_file_format=True)
    return path


@pytest.fixture(scope="session")
def data_dir():
    return Path(_DATA)
