"""
GhostStrike Report Studio - CLI
====================================
    python3 -m report_studio.cli --engagement <id> \\
        --variant {executive,technical,developer} --format html,md,json,sarif --out <dir>

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .data_sources import load_report_data
from .exporters import export_docx, export_html, export_json, export_pdf, export_sarif
from .variants import render_markdown


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="GhostStrike Report Studio")
    parser.add_argument("--engagement", "-e", required=True)
    parser.add_argument("--variant", "-v", default="technical",
                         choices=["executive", "technical", "developer", "remediation", "retest"])
    parser.add_argument("--format", "-f", default="md",
                         help="Comma-separated: html,md,json,sarif")
    parser.add_argument("--out", "-o", default=".")
    args = parser.parse_args(argv)

    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    unknown = [f for f in formats if f not in ("html", "md", "json", "sarif", "docx", "pdf")]
    if unknown:
        print(f"Unknown format(s): {unknown}", file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    data = load_report_data(args.engagement)
    markdown_text = render_markdown(args.variant, data)
    stem = f"{args.engagement}_{args.variant}"
    written = []

    if "md" in formats:
        md_path = out_dir / f"{stem}.md"
        md_path.write_text(markdown_text, encoding="utf-8")
        written.append(str(md_path))

    if "html" in formats:
        html_path = export_html(markdown_text, f"GhostStrike Report — {args.engagement}", out_dir / f"{stem}.html")
        written.append(str(html_path))

    if "json" in formats:
        json_path = export_json(data, out_dir / f"{stem}.json")
        written.append(str(json_path))

    if "sarif" in formats:
        try:
            sarif_path = export_sarif(data, out_dir / f"{stem}.sarif.json")
            written.append(str(sarif_path))
        except Exception as exc:
            print(f"[WARN] SARIF export failed: {exc}", file=sys.stderr)

    if "docx" in formats:
        docx_path = export_docx(data, f"GhostStrike Report — {args.engagement}", out_dir / f"{stem}.docx")
        written.append(str(docx_path))

    if "pdf" in formats:
        try:
            pdf_path = export_pdf(data, markdown_text, f"GhostStrike Report — {args.engagement}", out_dir / f"{stem}.pdf")
            written.append(str(pdf_path))
        except RuntimeError as exc:
            print(f"[WARN] PDF export failed: {exc}", file=sys.stderr)

    if not written:
        print("No formats produced any output.", file=sys.stderr)
        return 1

    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())