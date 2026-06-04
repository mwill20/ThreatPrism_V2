"""Extract Mermaid diagram sources from the docs into standalone .mmd files.

This keeps the rendered images in `assets/diagrams/` in sync with the Mermaid blocks
that live inline in the markdown docs (single source of truth = the markdown). Run this
to refresh the `.mmd` sources, then render to SVG/PNG with mermaid-cli:

    python tools/render_diagrams.py
    npx -y @mermaid-js/mermaid-cli -i assets/diagrams/src/<name>.mmd \
        -o assets/diagrams/<name>.svg -p assets/diagrams/src/puppeteer-config.json -b white

No network or Node is required for the extraction step itself.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "assets" / "diagrams" / "src"
OUT = ROOT / "assets" / "diagrams"

# (markdown source, 0-based index of the ```mermaid block in that file, output basename)
DIAGRAMS = [
    ("docs/ARCHITECTURE.md", 0, "architecture"),
    ("docs/ARCHITECTURE.md", 1, "case-lifecycle"),
    ("docs/ARCHITECTURE.md", 2, "data-model-er"),
    ("docs/threat-models/system-context.md", 0, "threat-model-dfd"),
    ("docs/threat-models/system-context.md", 1, "threat-model-overlay"),
]

_BLOCK = re.compile(r"```mermaid\n(.*?)\n```", re.DOTALL)


def main() -> int:
    SRC.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    for rel, idx, name in DIAGRAMS:
        blocks = _BLOCK.findall((ROOT / rel).read_text(encoding="utf-8"))
        if idx >= len(blocks):
            raise SystemExit(f"{rel}: expected a mermaid block at index {idx}, found {len(blocks)}")
        dest = SRC / f"{name}.mmd"
        dest.write_text(blocks[idx].strip() + "\n", encoding="utf-8")
        print(f"extracted {rel} [block {idx}] -> {dest.relative_to(ROOT)}")

    # Headless Chromium needs --no-sandbox in most CI/container environments.
    pconf = SRC / "puppeteer-config.json"
    pconf.write_text(json.dumps({"args": ["--no-sandbox", "--disable-setuid-sandbox"]}), encoding="utf-8")
    print(f"wrote {pconf.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
