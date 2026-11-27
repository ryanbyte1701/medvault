"""Fictional lab report PDFs in the style of Labcorp and Sonora Quest reports.

Every name, number, ID and address here is made up. The layouts follow the
public look of each lab's patient report (column headers and order) so the
parser can be tested without any real patient data.

    python tests/lab_samples.py out_dir   # writes the sample PDFs
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

W, H = letter


def _pdf(draw) -> bytes:
    b = io.BytesIO()
    c = canvas.Canvas(b, pagesize=letter)
    draw(c)
    c.save()
    return b.getvalue()


def labcorp(collected="03/14/2026", glucose="104", ldl="131", a1c="5.9", prev=True) -> bytes:
    """Newer Labcorp patient report: Current Result and Flag / Previous Result and Date."""

    def draw(c):
        y = H - 50
        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, "labcorp")
        c.setFont("Helvetica", 9)
        c.drawString(400, y, "Patient Report")
        y -= 22
        c.drawString(40, y, "Patient Name: DOE, JANE")
        c.drawString(300, y, "Specimen ID: 073-494-1234-0")
        y -= 13
        c.drawString(40, y, "DOB: 04/02/1980")
        c.drawString(160, y, "Age: 45")
        c.drawString(300, y, "Control ID: L1234567")
        y -= 13
        c.drawString(40, y, "Ordering Physician: R SMITH")
        c.drawString(300, y, f"Date collected: {collected} 0812 Local")
        y -= 13
        c.drawString(300, y, "Date received: 03/14/2026")
        y -= 13
        c.drawString(300, y, "Date reported: 03/16/2026")
        y -= 13
        c.drawString(40, y, "Fasting: Yes")
        y -= 26
        X = [40, 225, 320, 420, 490]

        def header(y):
            c.setFont("Helvetica-Bold", 8)
            for x, t in zip(X, ["Test", "Current Result and Flag", "Previous Result and Date", "Units", "Reference Interval"]):
                c.drawString(x, y, t)
            c.setFont("Helvetica", 9)

        def panel(y, name):
            c.setFont("Helvetica-Bold", 9)
            c.drawString(40, y, name)
            c.setFont("Helvetica", 9)

        def row(y, name, cur, prev_, unit, ref):
            c.drawString(X[0], y, name)
            c.drawString(X[0] + c.stringWidth(name, "Helvetica", 9) + 3, y, "01")  # performing-lab code
            c.drawString(X[1], y, cur)
            if prev and prev_:
                c.drawString(X[2], y, prev_)
            c.drawString(X[3], y, unit)
            c.drawString(X[4], y, ref)

        panel(y, "Comp. Metabolic Panel (14)")
        y -= 14
        header(y)
        y -= 14
        rows = [
            ("Glucose", f"{glucose} High", "97 09/20/2025", "mg/dL", "70-99"),
            ("BUN", "15", "13 09/20/2025", "mg/dL", "6-24"),
            ("Creatinine", "0.86", "0.82 09/20/2025", "mg/dL", "0.57-1.00"),
            ("eGFR", "84", "88 09/20/2025", "mL/min/1.73", ">59"),
            ("BUN/Creatinine Ratio", "17", "16 09/20/2025", "", "9-23"),
            ("Sodium", "139", "140 09/20/2025", "mmol/L", "134-144"),
            ("Potassium", "4.4", "4.1 09/20/2025", "mmol/L", "3.5-5.2"),
            ("Chloride", "102", "101 09/20/2025", "mmol/L", "96-106"),
            ("Carbon Dioxide, Total", "23", "24 09/20/2025", "mmol/L", "20-29"),
            ("Calcium", "9.5", "9.4 09/20/2025", "mg/dL", "8.7-10.2"),
            ("Protein, Total", "7.1", "", "g/dL", "6.0-8.5"),
            ("Albumin", "4.5", "", "g/dL", "3.9-4.9"),
            ("Globulin, Total", "2.6", "", "g/dL", "1.5-4.5"),
            ("Bilirubin, Total", "0.4", "", "mg/dL", "0.0-1.2"),
            ("Alkaline Phosphatase", "71", "", "IU/L", "44-121"),
            ("AST (SGOT)", "19", "", "IU/L", "0-40"),
            ("ALT (SGPT)", "23", "", "IU/L", "0-32"),
        ]
        for r in rows:
            row(y, *r)
            y -= 13
        y -= 8
        panel(y, "Lipid Panel")
        y -= 14
        header(y)
        y -= 14
        for r in [
            ("Cholesterol, Total", "212 High", "198 09/20/2025", "mg/dL", "100-199"),
            ("Triglycerides", "148", "122 09/20/2025", "mg/dL", "0-149"),
            ("HDL Cholesterol", "52", "55 09/20/2025", "mg/dL", ">39"),
            ("VLDL Cholesterol Cal", "29", "", "mg/dL", "5-40"),
            ("LDL Chol Calc (NIH)", f"{ldl} High", "119 09/20/2025", "mg/dL", "0-99"),
        ]:
            row(y, *r)
            y -= 13
        y -= 8
        panel(y, "Hemoglobin A1c")
        y -= 14
        header(y)
        y -= 14
        row(y, "Hemoglobin A1c", f"{a1c} High", "5.7 09/20/2025", "%", "4.8-5.6")
        y -= 13
        c.setFont("Helvetica", 7)
        c.drawString(40, y - 10, "Please Note: Prediabetes: 5.7 - 6.4  Diabetes: >6.4  Glycemic control for adults with diabetes: <7.0")
        c.drawString(40, 40, "Labcorp Burlington  1447 York Court, Burlington, NC 27215  (FICTIONAL SAMPLE REPORT - NOT REAL DATA)")
        c.showPage()
        # page 2: CBC, with the header repeated
        y = H - 50
        c.setFont("Helvetica", 9)
        c.drawString(40, y, "Patient Name: DOE, JANE   DOB: 04/02/1980   Specimen ID: 073-494-1234-0")
        y -= 26
        panel(y, "CBC With Differential/Platelet")
        y -= 14
        header(y)
        y -= 14
        for r in [
            ("WBC", "6.2", "5.8 09/20/2025", "x10E3/uL", "3.4-10.8"),
            ("RBC", "4.51", "", "x10E6/uL", "3.77-5.28"),
            ("Hemoglobin", "13.6", "13.9 09/20/2025", "g/dL", "11.1-15.9"),
            ("Hematocrit", "41.0", "", "%", "34.0-46.6"),
            ("MCV", "91", "", "fL", "79-97"),
            ("Platelets", "143 Low", "151 09/20/2025", "x10E3/uL", "150-450"),
            ("Neutrophils", "58", "", "%", "Not Estab."),
            ("Lymphs", "31", "", "%", "Not Estab."),
        ]:
            row(y, *r)
            y -= 13
        panel(y - 8, "Vitamin D, 25-Hydroxy")
        y -= 22
        header(y)
        y -= 14
        row(y, "Vitamin D, 25-Hydroxy", "24.1 Low", "", "ng/mL", "30.0-100.0")
        c.drawString(40, 40, "Page 2 of 2   FICTIONAL SAMPLE REPORT")
        c.showPage()

    return _pdf(draw)


def labcorp_classic() -> bytes:
    """Older Labcorp layout: Tests / Result / Flag / Units / Reference Interval / Lab."""

    def draw(c):
        y = H - 50
        c.setFont("Helvetica-Bold", 13)
        c.drawString(40, y, "LabCorp")
        c.setFont("Helvetica", 9)
        y -= 20
        c.drawString(40, y, "Patient: ROE, SAM")
        c.drawString(300, y, "Date collected: 11/02/2025")
        y -= 13
        c.drawString(40, y, "Date of Birth: 07/19/1975")
        c.drawString(300, y, "Date reported: 11/04/2025")
        y -= 26
        X = [40, 230, 300, 345, 420, 520]
        c.setFont("Helvetica-Bold", 8)
        for x, t in zip(X, ["TESTS", "RESULT", "FLAG", "UNITS", "REFERENCE INTERVAL", "LAB"]):
            c.drawString(x, y, t)
        c.setFont("Helvetica", 9)
        y -= 14
        c.drawString(40, y, "TSH+Free T4")
        y -= 13
        for name, val, flag, unit, ref in [
            ("TSH", "5.120", "High", "uIU/mL", "0.450-4.500"),
            ("T4,Free(Direct)", "1.02", "", "ng/dL", "0.82-1.77"),
            ("Ferritin", "18", "Low", "ng/mL", "30-400"),
            ("Vitamin B12", "512", "", "pg/mL", "232-1245"),
        ]:
            c.drawString(X[0], y, name)
            c.drawString(X[1], y, val)
            c.drawString(X[2], y, flag)
            c.drawString(X[3], y, unit)
            c.drawString(X[4], y, ref)
            c.drawString(X[5], y, "01")
            y -= 13
        c.drawString(40, 40, "01 BN  Labcorp Burlington  (FICTIONAL SAMPLE)")
        c.showPage()

    return _pdf(draw)


def sonora_quest(collected="06/09/2026", glucose="108", ldl="142") -> bytes:
    """Sonora Quest / Quest style: Test Name / In Range / Out Of Range / Reference Range / Lab."""

    def draw(c):
        y = H - 50
        c.setFont("Helvetica-Bold", 13)
        c.drawString(40, y, "Sonora Quest Laboratories")
        c.setFont("Helvetica", 8)
        c.drawString(360, y, "A Subsidiary of Banner Health (FICTIONAL SAMPLE)")
        y -= 20
        c.setFont("Helvetica", 9)
        c.drawString(40, y, "Patient Information")
        c.drawString(230, y, "Specimen Information")
        c.drawString(420, y, "Client Information")
        y -= 13
        c.drawString(40, y, "DOE, JANE")
        c.drawString(230, y, "Specimen: SQ123456A")
        c.drawString(420, y, "Client #: 99999999")
        y -= 13
        c.drawString(40, y, "DOB: 04/02/1980   AGE: 46")
        c.drawString(230, y, f"Collected: {collected} / 07:45 MST")
        c.drawString(420, y, "Ordering Physician:")
        y -= 13
        c.drawString(40, y, "Gender: F")
        c.drawString(230, y, "Received: 06/09/2026 / 09:12 MST")
        c.drawString(420, y, "LEE, MORGAN")
        y -= 13
        c.drawString(40, y, "Fasting: Y")
        c.drawString(230, y, "Reported: 06/10/2026 / 05:30 MST")
        y -= 26
        X = [40, 230, 300, 380, 540]

        def header(y):
            c.setFont("Helvetica-Bold", 8)
            for x, t in zip(X, ["Test Name", "In Range", "Out Of Range", "Reference Range", "Lab"]):
                c.drawString(x, y, t)
            c.setFont("Helvetica", 9)

        def row(y, name, inr, outr, ref, lab="SQ"):
            c.drawString(X[0], y, name)
            if inr:
                c.drawString(X[1], y, inr)
            if outr:
                c.drawString(X[2], y, outr)
            c.drawString(X[3], y, ref)
            c.drawString(X[4], y, lab)

        header(y)
        y -= 14
        c.setFont("Helvetica-Bold", 9)
        c.drawString(40, y, "COMPREHENSIVE METABOLIC PANEL")
        c.setFont("Helvetica", 9)
        y -= 13
        for r in [
            ("GLUCOSE", "", f"{glucose} H", "65-99 mg/dL"),
            ("UREA NITROGEN (BUN)", "14", "", "7-25 mg/dL"),
            ("CREATININE", "0.84", "", "0.50-1.03 mg/dL"),
            ("EGFR", "86", "", "> OR = 60 mL/min/1.73m2"),
            ("SODIUM", "140", "", "135-146 mmol/L"),
            ("POTASSIUM", "4.2", "", "3.5-5.3 mmol/L"),
            ("CHLORIDE", "103", "", "98-110 mmol/L"),
            ("CARBON DIOXIDE", "25", "", "20-32 mmol/L"),
            ("CALCIUM", "9.6", "", "8.6-10.4 mg/dL"),
            ("ALT", "24", "", "6-29 U/L"),
            ("AST", "20", "", "10-35 U/L"),
        ]:
            row(y, *r)
            y -= 13
        y -= 6
        c.setFont("Helvetica-Bold", 9)
        c.drawString(40, y, "LIPID PANEL, STANDARD")
        c.setFont("Helvetica", 9)
        y -= 13
        for r in [
            ("CHOLESTEROL, TOTAL", "", "221 H", "<200 mg/dL"),
            ("HDL CHOLESTEROL", "54", "", "> OR = 50 mg/dL"),
            ("TRIGLYCERIDES", "", "160 H", "<150 mg/dL"),
            ("LDL-CHOLESTEROL", "", f"{ldl} H", "mg/dL (calc)"),
            ("CHOL/HDLC RATIO", "4.1", "", "<5.0 (calc)"),
            ("NON HDL CHOLESTEROL", "", "167 H", "<130 mg/dL (calc)"),
        ]:
            row(y, *r)
            y -= 13
        y -= 6
        row(y, "HEMOGLOBIN A1c", "", "6.1 H", "<5.7 % of total Hgb")
        y -= 13
        row(y, "TSH", "2.10", "", "0.40-4.50 mIU/L")
        y -= 13
        row(y, "VITAMIN D,25-OH,TOTAL,IA", "", "26 L", "30-100 ng/mL")
        y -= 20
        c.setFont("Helvetica", 7)
        c.drawString(40, y, "For patients >17 years of age, the reference range for LDL is <100 mg/dL.")
        c.drawString(40, 40, "PERFORMING SITE: SQ  SONORA QUEST LABORATORIES, 424 S FICTION ST, TEMPE AZ  (FICTIONAL SAMPLE REPORT)")
        c.showPage()

    return _pdf(draw)


def scanned(pdf: bytes, dpi: int = 200) -> bytes:
    """Rasterize a PDF and wrap the pictures in a new PDF with no text layer."""
    import pypdfium2 as pdfium
    from reportlab.lib.utils import ImageReader

    doc = pdfium.PdfDocument(pdf)
    imgs = [doc[i].render(scale=dpi / 72).to_pil().convert("L") for i in range(len(doc))]
    doc.close()

    def draw(c):
        for im in imgs:
            c.drawImage(ImageReader(im), 0, 0, W, H)
            c.showPage()

    return _pdf(draw)


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    (out / "sample-labcorp.pdf").write_bytes(labcorp())
    (out / "sample-labcorp-classic.pdf").write_bytes(labcorp_classic())
    (out / "sample-sonora-quest.pdf").write_bytes(sonora_quest())
    (out / "sample-labcorp-scanned.pdf").write_bytes(scanned(labcorp()))
    print("wrote samples to", out)
