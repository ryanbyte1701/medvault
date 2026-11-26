#!/usr/bin/env python3
"""Bundle the web UI with an in-browser mock API into one self-contained HTML
file (no server, sample data only). Used for the interactive preview.

    python3 tools/build_demo.py preview/scanvault-preview.html
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"


def main(out: str) -> None:
    css = (STATIC / "styles.css").read_text()
    app = (STATIC / "app.js").read_text()
    demo = (ROOT / "tools" / "demo" / "demo.js").read_text()
    icon = (STATIC / "icon.svg").read_text()
    import base64

    favicon = "data:image/svg+xml;base64," + base64.b64encode(icon.encode()).decode()
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScanVault preview</title>
<link rel="icon" href="{favicon}">
<style>
{css}
</style>
</head>
<body>
<div id="app" aria-live="polite"></div>
<div id="toast" role="status"></div>
<script>
{demo}
</script>
<script>
{app}
</script>
</body>
</html>
"""
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(html)
    print(f"wrote {out} ({len(html):,} bytes)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "preview/scanvault-preview.html")
