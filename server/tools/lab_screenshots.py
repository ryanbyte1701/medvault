#!/usr/bin/env python3
"""Regenerate the LabsVault README screenshots (labs, labs-review, labs-trend).

The demo has no labs, so this seeds a throwaway server with the fictional sample
reports from tests/lab_samples.py. Start an empty server first, then run:

    MEDVAULT_DATA=$(mktemp -d) MEDVAULT_SETUP_CODE=SHOT-CODE-0001 MEDVAULT_COOKIE_SECURE=0 \
        python -m uvicorn app.main:app --port 8099 &
    python3 tools/lab_screenshots.py .
"""
import asyncio, os, sys, json, subprocess, tempfile, time
from pathlib import Path
sys.path.insert(0, sys.argv[1] + "/tests")
import lab_samples
import requests
from PIL import Image
from playwright.async_api import async_playwright
ROOT = Path(sys.argv[1]); OUT = ROOT / "docs/screenshots"
H = {"X-MedVault": "1"}
DARK = {"theme": "dark", "dark_color": "#0d1416"}

def seed(base):
    s = requests.Session()
    r = s.post(base + "/api/setup", json={"username": "ryan", "password": "sample-password-1", "passphrase": "orbit-cedar-lantern-quill"}, headers={**H, "X-Setup-Code": "SHOT-CODE-0001"}); r.raise_for_status()
    s.put(base + "/api/prefs", json=DARK, headers=H)
    p = s.post(base + "/api/patients", json={"name": "Jane Doe", "date_of_birth": "1980-04-02"}, headers=H).json()
    for pdf in (lab_samples.labcorp(), lab_samples.sonora_quest()):
        d = s.post(f"{base}/api/patients/{p['id']}/labs/upload", files=[("file", ("labs.pdf", pdf, "application/pdf"))], headers=H).json()
        s.put(f"{base}/api/labs/reports/{d['id']}", json={"save": True}, headers=H).raise_for_status()
    d = s.post(f"{base}/api/patients/{p['id']}/labs/upload", files=[("file", ("labs.pdf", lab_samples.labcorp(collected="10/02/2026", glucose="101", ldl="128", a1c="6.1"), "application/pdf"))], headers=H).json()
    return p

async def shot(pg, name):
    await pg.wait_for_timeout(700)
    path = OUT / f"{name}.png"
    await pg.screenshot(path=str(path))
    Image.open(path).convert("RGB").quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(path, optimize=True)
    print("wrote", path)

async def main(base, p):
    async with async_playwright() as pw:
        kw = {"executable_path": os.environ["CHROME"]} if os.environ.get("CHROME") else {}
        b = await pw.chromium.launch(args=["--no-sandbox"], **kw)
        ctx = await b.new_context(viewport={"width": 1440, "height": 1000}, color_scheme="dark")
        await ctx.add_init_script(f"localStorage.setItem('sv-theme', '{json.dumps(DARK)}')")
        pg = await ctx.new_page()
        await pg.goto(base + "/")
        await pg.wait_for_timeout(800)
        await pg.fill("input[name=u], input[name=username]", "ryan")
        await pg.fill("input[type=password]", "sample-password-1")
        await pg.keyboard.press("Enter")
        await pg.wait_for_timeout(1500)
        if await pg.get_by_text("Remind me later").count():
            await pg.get_by_text("Remind me later").click(); await pg.wait_for_timeout(600)
        await pg.goto(f"{base}/#/labs/{p['id']}"); await pg.wait_for_timeout(1500)
        await shot(pg, "labs")
        await pg.get_by_text("Review Labcorp").first.click(); await pg.wait_for_timeout(1200)
        await shot(pg, "labs-review")
        await pg.keyboard.press("Escape"); await pg.wait_for_timeout(600)
        await pg.locator("[data-an=ldl]").first.scroll_into_view_if_needed(); await pg.locator("[data-an=ldl]").first.click(); await pg.wait_for_timeout(1200)
        await shot(pg, "labs-trend")
        await b.close()

base = "http://127.0.0.1:8099"
p = seed(base)
asyncio.run(main(base, p))
