"""Public presentation metadata from the existing registry; no GT is dispatched."""
from pathlib import Path
import ast
import sys

path = str(Path(__file__).resolve().parents[1])
if path not in sys.path:
    sys.path.insert(0, path)
from v2.registry import SCENARIO_REGISTRY_V2

CATALOG = [{k: r.get(k) for k in ("id", "label", "module", "evidence", "notes", "external_tool", "reuse")}
           for r in SCENARIO_REGISTRY_V2]
for row in CATALOG:
    if row["module"]:
        source = Path(path).joinpath(*row["module"].split(".")).with_suffix(".py")
        doc = ast.get_docstring(ast.parse(source.read_text(encoding="utf-8"))) or ""
        row["description"] = "\n".join(doc.splitlines()[:10])


def group(letter):
    return [r for r in CATALOG if r["id"].startswith(letter.lower())]
