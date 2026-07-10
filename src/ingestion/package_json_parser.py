import json
from pathlib import Path
from typing import List, Dict


def parse_package_json(path: str, asset_id: str, include_dev: bool = False) -> List[Dict]:
    path_obj = Path(path)

    if not path_obj.exists():
        raise FileNotFoundError(f"package.json not found: {path}")

    data = json.loads(path_obj.read_text(encoding="utf-8"))
    components = []

    dependency_groups = [("dependencies", "runtime")]

    if include_dev:
        dependency_groups.append(("devDependencies", "development"))

    for group_name, dep_type in dependency_groups:
        deps = data.get(group_name, {})

        for name, version in deps.items():
            cleaned_version = str(version).replace("^", "").replace("~", "").strip()

            components.append({
                "asset_id": asset_id,
                "component_name": name.lower(),
                "version": cleaned_version,
                "ecosystem": "npm",
                "source_file": str(path_obj),
                "dependency_type": dep_type,
                "extraction_confidence": "Medium" if version != cleaned_version else "High",
                "validation_issue": "Version range/operator cleaned" if version != cleaned_version else None
            })

    return components
