"""Render README screenshots (SVG) from real anyz output.

    pip install rich
    python docs/make_screenshots.py [path/to/anyz]

Each screenshot runs anyz with FORCE_COLOR=1 on a test fixture and converts the
ANSI output to SVG with rich, so the images always match what the tool prints.
"""

import io
import os
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.text import Text

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures" / "bin"
OUT = ROOT / "docs" / "screenshots"
WIDTH = 100

# (file name, fixture, arguments, terminal width)
SHOTS = [
    ("info", "elf-x64-vuln", [], WIDTH),
    ("auto", "elf-x64-vuln", ["--auto"], WIDTH),
    ("disasm", "elf-x64-vuln", ["-d", "main"], 112),
    ("checksec-pe", "pe-x64-msvc.exe", ["--checksec"], WIDTH),
    ("sections", "pe-x64-mingw.exe", ["--sections"], WIDTH),
    ("imports", "pe-x64-mingw.exe", ["--imports"], WIDTH),
    ("hexdump", "elf-x64-vuln", ["-x", "main", "64"], WIDTH),
    ("gadgets", "elf-x64-static", ["-g"], 112),
]


def main() -> None:
    exe = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "target" / "release" / ("anyz.exe" if os.name == "nt" else "anyz"))
    OUT.mkdir(parents=True, exist_ok=True)
    for name, fixture, args, width in SHOTS:
        # Run from the fixture directory so paths in the output stay short.
        cmd = [exe, fixture, *args]
        env = dict(os.environ, FORCE_COLOR="1", COLUMNS=str(width))
        env.pop("NO_COLOR", None)
        out = subprocess.run(cmd, cwd=FIX, env=env, capture_output=True, text=True, encoding="utf-8", check=True).stdout
        lines = out.splitlines()
        if name == "auto":
            # The info panel has its own screenshot; keep the findings.
            start = next(i for i, l in enumerate(lines) if "Findings" in l)
            lines = lines[start:]
        if len(lines) > 34:
            lines = lines[:34] + ["\x1b[90m...\x1b[0m"]
        console = Console(record=True, width=width, force_terminal=True, color_system="truecolor", file=io.StringIO())
        console.print(Text.from_ansi("\n".join(lines)), soft_wrap=True)
        title = "$ anyz " + " ".join([fixture, *args])
        svg = console.export_svg(title=title)
        # Fira Code ligatures would render "0x" as "0×": turn them off.
        svg = svg.replace(
            "font-family: Fira Code, monospace;",
            "font-family: Fira Code, monospace; font-variant-ligatures: none; font-feature-settings: 'liga' 0, 'calt' 0;",
        )
        (OUT / f"{name}.svg").write_text(svg, encoding="utf-8")
        print(f"wrote docs/screenshots/{name}.svg ({len(lines)} lines)")


if __name__ == "__main__":
    main()
