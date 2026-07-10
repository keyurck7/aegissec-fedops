from pathlib import Path
from packaging.requirements import Requirement
from typing import List, Dict


def parse_requirements_file(path: str, asset_id: str) -> List[Dict]:
    path_obj = Path(path)
    components = []

    if not path_obj.exists():
        raise FileNotFoundError(f"Requirements file not found: {path}")

    for line_no, raw_line in enumerate(path_obj.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        try:
            req = Requirement(line)
            version = None

            for spec in req.specifier:
                if spec.operator == "==":
                    version = spec.version
                    break

            components.append({
                "asset_id": asset_id,
                "component_name": req.name.lower(),
                "version": version,
                "ecosystem": "PyPI",
                "source_file": str(path_obj),
                "source_line": line_no,
                "dependency_type": "runtime",
                "extraction_confidence": "High" if version else "Medium",
                "validation_issue": None if version else "Missing pinned version"
            })

        except Exception as exc:
            components.append({
                "asset_id": asset_id,
                "component_name": line,
                "version": None,
                "ecosystem": "PyPI",
                "source_file": str(path_obj),
                "source_line": line_no,
                "dependency_type": "unknown",
                "extraction_confidence": "Low",
                "validation_issue": f"Could not parse requirement: {exc}"
            })

    return components
