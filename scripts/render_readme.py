"""Copy the generated result tables into README.md between the RESULTS markers, so every number in
the README comes from outputs/ and nothing is typed by hand."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
readme = ROOT / "README.md"
text = readme.read_text()
for name, src in (("SCANS", "outputs/summary.md"), ("REDTEAM", "outputs/redteam/summary.md")):
    start, end = f"<!-- {name}:START -->", f"<!-- {name}:END -->"
    body = (ROOT / src).read_text().strip()
    head, rest = text.split(start, 1)
    _, tail = rest.split(end, 1)
    text = f"{head}{start}\n{body}\n{end}{tail}"
readme.write_text(text)
print("README.md updated from outputs/")
