from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_EXACT_SEMVER_RE = re.compile(
    r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


def _classify_npm_specifier(value: str) -> tuple[str, str | None, str | None]:
    specifier = value.strip()
    if _EXACT_SEMVER_RE.fullmatch(specifier):
        return "exact", specifier, None
    lower = specifier.casefold()
    if lower.startswith(("git+", "http://", "https://", "file:", "github:")):
        return "direct_reference", None, "Direct or VCS dependency requires provenance approval"
    if specifier in {"*", "latest", "next"}:
        return "mutable_tag", None, "Mutable npm tag or wildcard is prohibited"
    return "range", None, "Version range is not an immutable resolved version"


def parse_package_json(
    path: str,
    asset_id: str,
    include_dev: bool = False,
) -> list[dict[str, Any]]:
    path_obj = Path(path)

    if not path_obj.exists():
        raise FileNotFoundError(f"package.json not found: {path}")

    data = json.loads(path_obj.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("package.json root must be an object")

    components: list[dict[str, Any]] = []
    dependency_groups = [("dependencies", "runtime")]

    if include_dev:
        dependency_groups.append(("devDependencies", "development"))

    for group_name, dep_type in dependency_groups:
        deps = data.get(group_name, {})
        if not isinstance(deps, dict):
            raise ValueError(f"package.json {group_name} must be an object")

        for name, raw_version in deps.items():
            specifier = str(raw_version).strip()
            specifier_type, resolved_version, issue = _classify_npm_specifier(specifier)

            components.append(
                {
                    "asset_id": asset_id,
                    "component_name": str(name).lower(),
                    "version": resolved_version,
                    "ecosystem": "npm",
                    "source_file": str(path_obj),
                    "dependency_type": dep_type,
                    "extraction_confidence": "High" if resolved_version else "Medium",
                    "validation_issue": issue,
                    "requested_version": specifier,
                    "specifier_type": specifier_type,
                    "is_exact_pin": resolved_version is not None,
                }
            )

    return components
