"""Common lab analytes: a stable key, a display name, a LOINC code and the
names Labcorp, Quest and Sonora Quest print for them.

LOINC codes are the usual codes for the serum/plasma or whole-blood test as
reported by the big US reference labs. They are shown for reference and used
to group results; a lab may use a more specific code for its own method.
Analytes that are not in this list still work: they get a key made from the
printed name, and the user can map them to a catalog entry while reviewing.
"""
from __future__ import annotations

import re

# key, display name, LOINC, panel, aliases (as printed, any case)
_ROWS: list[tuple[str, str, str, str, tuple[str, ...]]] = [
    # --- metabolic panel
    ("glucose", "Glucose", "2345-7", "Metabolic", ("glucose", "glucose, serum", "glucose, plasma", "glucose, fasting", "fasting glucose", "glucose fasting")),
    ("bun", "BUN (urea nitrogen)", "3094-0", "Metabolic", ("bun", "urea nitrogen", "urea nitrogen (bun)", "blood urea nitrogen", "urea nitrogen, blood")),
    ("creatinine", "Creatinine", "2160-0", "Metabolic", ("creatinine", "creatinine, serum")),
    ("egfr", "eGFR", "98979-8", "Metabolic", ("egfr", "egfr if nonafricn am", "egfr non-afr. american", "egfr ckd-epi", "estimated gfr", "egfr (ckd-epi 2021)", "egfr creatinine", "gfr, estimated")),
    ("bun_creatinine_ratio", "BUN/Creatinine ratio", "3097-3", "Metabolic", ("bun/creatinine ratio", "bun/creat ratio", "bun/creatinine ratio (calc)")),
    ("sodium", "Sodium", "2951-2", "Metabolic", ("sodium", "sodium, serum", "na")),
    ("potassium", "Potassium", "2823-3", "Metabolic", ("potassium", "potassium, serum", "k")),
    ("chloride", "Chloride", "2075-0", "Metabolic", ("chloride", "chloride, serum", "cl")),
    ("co2", "Carbon dioxide (CO2)", "2028-9", "Metabolic", ("carbon dioxide", "carbon dioxide, total", "co2", "carbon dioxide (co2)", "bicarbonate")),
    ("calcium", "Calcium", "17861-6", "Metabolic", ("calcium", "calcium, serum", "ca")),
    ("protein_total", "Protein, total", "2885-2", "Metabolic", ("protein, total", "total protein", "protein, total, serum")),
    ("albumin", "Albumin", "1751-7", "Metabolic", ("albumin", "albumin, serum")),
    ("globulin", "Globulin", "10834-0", "Metabolic", ("globulin", "globulin, total", "globulin (calc)")),
    ("ag_ratio", "A/G ratio", "1759-0", "Metabolic", ("a/g ratio", "albumin/globulin ratio", "albumin/globulin ratio (calc)")),
    ("bilirubin_total", "Bilirubin, total", "1975-2", "Liver", ("bilirubin, total", "total bilirubin", "bilirubin total")),
    ("bilirubin_direct", "Bilirubin, direct", "1968-7", "Liver", ("bilirubin, direct", "direct bilirubin")),
    ("alp", "Alkaline phosphatase", "6768-6", "Liver", ("alkaline phosphatase", "alk phos", "alkaline phosphatase, s", "alp")),
    ("ast", "AST (SGOT)", "1920-8", "Liver", ("ast", "ast (sgot)", "sgot", "ast(sgot)")),
    ("alt", "ALT (SGPT)", "1742-6", "Liver", ("alt", "alt (sgpt)", "sgpt", "alt(sgpt)")),
    ("ggt", "GGT", "2324-2", "Liver", ("ggt", "gamma-glutamyl transferase", "ggt (gamma glutamyl transferase)")),
    ("magnesium", "Magnesium", "19123-9", "Metabolic", ("magnesium", "magnesium, serum")),
    ("phosphorus", "Phosphorus", "2777-1", "Metabolic", ("phosphorus", "phosphorus, serum", "phosphate (as phosphorus)")),
    ("uric_acid", "Uric acid", "3084-1", "Metabolic", ("uric acid", "uric acid, serum")),
    # --- lipids
    ("cholesterol_total", "Cholesterol, total", "2093-3", "Lipids", ("cholesterol, total", "total cholesterol", "cholesterol")),
    ("triglycerides", "Triglycerides", "2571-8", "Lipids", ("triglycerides", "triglyceride")),
    ("hdl", "HDL cholesterol", "2085-9", "Lipids", ("hdl cholesterol", "hdl chol", "hdl", "hdl-c")),
    ("ldl", "LDL cholesterol", "13457-7", "Lipids", ("ldl chol calc (nih)", "ldl cholesterol", "ldl-cholesterol", "ldl cholesterol calc", "ldl chol calc", "ldl-c", "ldl", "ldl cholesterol (calc)")),
    ("vldl", "VLDL cholesterol", "13458-5", "Lipids", ("vldl cholesterol cal", "vldl chol cal", "vldl cholesterol", "vldl")),
    ("non_hdl", "Non-HDL cholesterol", "43396-1", "Lipids", ("non hdl cholesterol", "non-hdl cholesterol", "non hdl chol. (calc)", "non-hdl cholesterol (calc)", "non hdl cholesterol (calc)")),
    ("chol_hdl_ratio", "Cholesterol/HDL ratio", "9830-1", "Lipids", ("chol/hdlc ratio", "t. chol/hdl ratio", "chol/hdl ratio", "cholesterol/hdl ratio", "chol/hdlc ratio (calc)")),
    ("apob", "Apolipoprotein B", "1884-6", "Lipids", ("apolipoprotein b", "apob", "apo b")),
    ("lpa", "Lipoprotein (a)", "10835-7", "Lipids", ("lipoprotein (a)", "lipoprotein(a)", "lp(a)")),
    # --- CBC
    ("wbc", "WBC", "6690-2", "CBC", ("wbc", "white blood cell count", "white blood cells", "wbc count")),
    ("rbc", "RBC", "789-8", "CBC", ("rbc", "red blood cell count", "red blood cells", "rbc count")),
    ("hemoglobin", "Hemoglobin", "718-7", "CBC", ("hemoglobin", "hgb", "hemoglobin (hgb)")),
    ("hematocrit", "Hematocrit", "4544-3", "CBC", ("hematocrit", "hct", "hematocrit (hct)")),
    ("mcv", "MCV", "787-2", "CBC", ("mcv",)),
    ("mch", "MCH", "785-6", "CBC", ("mch",)),
    ("mchc", "MCHC", "786-4", "CBC", ("mchc",)),
    ("rdw", "RDW", "788-0", "CBC", ("rdw", "rdw-cv")),
    ("platelets", "Platelets", "777-3", "CBC", ("platelets", "platelet count", "plt")),
    ("mpv", "MPV", "32623-1", "CBC", ("mpv",)),
    ("neutrophils_pct", "Neutrophils %", "770-8", "CBC", ("neutrophils", "neutrophils %", "neutrophils, %", "segmented neutrophils")),
    ("lymphocytes_pct", "Lymphocytes %", "736-9", "CBC", ("lymphs", "lymphocytes", "lymphocytes %", "lymphocytes, %")),
    ("monocytes_pct", "Monocytes %", "5905-5", "CBC", ("monocytes", "monocytes %", "monocytes, %")),
    ("eosinophils_pct", "Eosinophils %", "713-8", "CBC", ("eos", "eosinophils", "eosinophils %", "eosinophils, %")),
    ("basophils_pct", "Basophils %", "706-2", "CBC", ("basos", "basophils", "basophils %", "basophils, %")),
    ("neutrophils_abs", "Neutrophils (absolute)", "751-8", "CBC", ("neutrophils (absolute)", "absolute neutrophils", "neutrophils, absolute", "absolute neutrophil count", "anc")),
    ("lymphocytes_abs", "Lymphocytes (absolute)", "731-0", "CBC", ("lymphs (absolute)", "absolute lymphocytes", "lymphocytes, absolute", "lymphocytes (absolute)")),
    ("monocytes_abs", "Monocytes (absolute)", "742-7", "CBC", ("monocytes(absolute)", "monocytes (absolute)", "absolute monocytes", "monocytes, absolute")),
    ("eosinophils_abs", "Eosinophils (absolute)", "711-2", "CBC", ("eos (absolute)", "absolute eosinophils", "eosinophils, absolute", "eosinophils (absolute)")),
    ("basophils_abs", "Basophils (absolute)", "704-7", "CBC", ("baso (absolute)", "basos (absolute)", "absolute basophils", "basophils, absolute", "basophils (absolute)")),
    ("immature_granulocytes_pct", "Immature granulocytes %", "71695-1", "CBC", ("immature granulocytes", "immature granulocytes %", "immature grans")),
    # --- diabetes
    ("hba1c", "Hemoglobin A1c", "4548-4", "Diabetes", ("hemoglobin a1c", "hba1c", "a1c", "hemoglobin a1c (hba1c)", "glycohemoglobin")),
    ("eag", "Estimated average glucose", "27353-2", "Diabetes", ("estim. avg glu (eag)", "estimated average glucose", "eag", "estimated average glucose (eag)")),
    ("insulin", "Insulin", "20448-7", "Diabetes", ("insulin", "insulin, fasting")),
    # --- thyroid
    ("tsh", "TSH", "3016-3", "Thyroid", ("tsh", "tsh, 3rd generation", "thyroid stimulating hormone", "tsh w/reflex to ft4")),
    ("t4_free", "Free T4", "3024-7", "Thyroid", ("t4,free(direct)", "t4, free (direct)", "free t4", "t4, free", "thyroxine (t4), free", "t4 free")),
    ("t3_free", "Free T3", "3051-0", "Thyroid", ("triiodothyronine,free,serum", "free t3", "t3, free", "triiodothyronine (t3), free")),
    ("t4_total", "T4, total", "3026-2", "Thyroid", ("t4, total", "thyroxine (t4)", "t4")),
    # --- vitamins, iron
    ("vitamin_d", "Vitamin D, 25-hydroxy", "62292-8", "Vitamins", ("vitamin d, 25-hydroxy", "vitamin d 25-hydroxy", "vitamin d,25-oh,total,ia", "vitamin d, 25-oh, total", "25-oh vitamin d (total)", "vitamin d, 25-oh, total, ia", "25-hydroxyvitamin d", "vitamin d 25 oh")),
    ("vitamin_b12", "Vitamin B12", "2132-9", "Vitamins", ("vitamin b12", "vitamin b-12", "cobalamin")),
    ("folate", "Folate", "2284-8", "Vitamins", ("folate", "folate (folic acid), serum", "folic acid")),
    ("ferritin", "Ferritin", "2276-4", "Iron", ("ferritin", "ferritin, serum")),
    ("iron", "Iron", "2498-4", "Iron", ("iron", "iron, total", "iron, serum")),
    ("tibc", "TIBC", "2500-7", "Iron", ("tibc", "iron bind.cap.(tibc)", "total iron binding capacity", "iron binding capacity")),
    ("iron_saturation", "Iron saturation", "2502-3", "Iron", ("iron saturation", "% saturation", "iron saturation (calc)", "transferrin saturation")),
    ("uibc", "UIBC", "2501-5", "Iron", ("uibc",)),
    # --- other common
    ("psa", "PSA", "2857-1", "Other", ("psa", "prostate specific ag", "psa, total", "prostate specific antigen")),
    ("crp", "C-reactive protein", "1988-5", "Inflammation", ("c-reactive protein", "crp", "c-reactive protein, quant")),
    ("hscrp", "hs-CRP", "30522-7", "Inflammation", ("hs crp", "hs-crp", "c-reactive protein, cardiac", "crp, high sensitivity")),
    ("homocysteine", "Homocysteine", "13965-9", "Other", ("homocyst(e)ine", "homocysteine")),
    ("testosterone_total", "Testosterone, total", "2986-8", "Hormones", ("testosterone", "testosterone, total", "testosterone, serum", "testosterone, total, ms")),
    ("estradiol", "Estradiol", "2243-4", "Hormones", ("estradiol",)),
    ("cortisol", "Cortisol", "2143-6", "Hormones", ("cortisol", "cortisol, total")),
    ("ck", "Creatine kinase", "2157-6", "Other", ("creatine kinase", "ck", "ck, total", "creatine kinase,total")),
    ("ldh", "LDH", "2532-0", "Other", ("ld", "ldh", "lactate dehydrogenase")),
    ("lipase", "Lipase", "3040-3", "Other", ("lipase",)),
    ("amylase", "Amylase", "1798-8", "Other", ("amylase",)),
    ("uacr", "Albumin/creatinine ratio, urine", "9318-7", "Urine", ("albumin/creatinine ratio", "microalb/creat ratio", "albumin/creatinine ratio, random urine", "microalb/creat ratio, urine")),
]

FLAGS = {
    "h": "H", "high": "H", "hi": "H", "l": "L", "low": "L", "lo": "L",
    "a": "A", "abnormal": "A", "abn": "A",
    "hh": "HH", "ll": "LL", "c": "C", "critical": "C", "critical high": "HH", "critical low": "LL",
}

_NOISE = re.compile(r"\b(serum|plasma|blood|s|p|b|qn|quant|quantitative)\b")


def normalize(name: str) -> str:
    """Lowercase a printed test name and drop footnote marks and spacing."""
    n = (name or "").lower().replace("–", "-").replace(" ", " ")
    n = re.sub(r"[¹²³⁰-⁹]+", "", n)  # superscript footnote digits
    n = re.sub(r"\s+0\d$", "", n)  # trailing Labcorp lab code (01, 02)
    n = re.sub(r"\s*\(\s*", " (", n)
    n = re.sub(r"\s*\)\s*", ") ", n)
    n = re.sub(r"\s*,\s*", ", ", n)
    n = re.sub(r"\ba[il1]c\b", "a1c", n)  # OCR reads A1c as Aic / Alc
    n = re.sub(r"\s+", " ", n).strip(" ,.:;*")
    return n


CATALOG: dict[str, dict] = {}
_ALIASES: dict[str, str] = {}
for key, display, loinc, panel, aliases in _ROWS:
    CATALOG[key] = {"key": key, "name": display, "loinc": loinc, "panel": panel}
    for a in (display, *aliases):
        _ALIASES.setdefault(normalize(a), key)
_BY_LOINC = {v["loinc"]: k for k, v in CATALOG.items()}


def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", normalize(name)).strip("_")
    return ("x_" + s)[:64] if s else "x_unknown"


def lookup(name: str, extra: dict | None = None) -> str | None:
    """Catalog key for a printed test name, or None. extra holds the user's
    own remembered mappings (normalized name -> key)."""
    n = normalize(name)
    if not n:
        return None
    if extra and n in extra:
        return extra[n]
    if n in _ALIASES:
        return _ALIASES[n]
    for cand in (re.sub(r"\s*\([^)]*\)\s*$", "", n), re.sub(r",\s*[a-z ]+$", "", n), _NOISE.sub("", n).replace(" ,", ",")):
        cand = re.sub(r"\s+", " ", cand).strip(" ,")
        if cand in _ALIASES:
            return _ALIASES[cand]
    return None


def key_for(name: str, extra: dict | None = None) -> str:
    return lookup(name, extra) or slug(name)


def info(key: str) -> dict | None:
    return CATALOG.get(key)


def by_loinc(code: str) -> str | None:
    return _BY_LOINC.get(code)


def parse_flag(tok: str | None) -> str | None:
    if not tok:
        return None
    return FLAGS.get(tok.strip().lower().strip("*!"))
