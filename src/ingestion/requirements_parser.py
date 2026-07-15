from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement


_HASH_RE = re.compile(r"--hash=(sha256):([0-9a-fA-F]{64})")


def _logical_requirement_lines(text: str) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    buffer = ""
    start_line = 0

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not buffer:
            start_line = line_number
        continuation = stripped.endswith("\\")
        fragment = stripped[:-1].strip() if continuation else stripped
        buffer = f"{buffer} {fragment}".strip()
        if not continuation:
            logical.append((start_line, buffer))
            buffer = ""

    if buffer:
        logical.append((start_line, buffer))

    return logical


def _split_hash_options(line: str) -> tuple[str, dict[str, list[str]]]:
    hashes: dict[str, list[str]] = {}
    for algorithm, digest in _HASH_RE.findall(line):
        hashes.setdefault(algorithm.lower(), []).append(digest.lower())
    requirement_text = _HASH_RE.sub("", line)
    requirement_text = re.sub(r"\s+", " ", requirement_text).strip()
    return requirement_text, hashes


def _exact_pin(requirement: Requirement) -> str | None:
    specifiers = list(requirement.specifier)
    if len(specifiers) != 1:
        return None
    specifier = specifiers[0]
    if specifier.operator != "==" or "*" in specifier.version:
        return None
    return specifier.version


def parse_requirements_file(
    path: str,
    asset_id: str,
    *,
    strict_supply_chain: bool = False,
) -> list[dict[str, Any]]:
    path_obj = Path(path)
    components: list[dict[str, Any]] = []

    if not path_obj.exists():
        raise FileNotFoundError(f"Requirements file not found: {path}")

    for line_no, logical_line in _logical_requirement_lines(
        path_obj.read_text(encoding="utf-8")
    ):
        if logical_line.startswith(("-", "--")):
            components.append(
                {
                    "asset_id": asset_id,
                    "component_name": logical_line,
                    "version": None,
                    "ecosystem": "PyPI",
                    "source_file": str(path_obj),
                    "source_line": line_no,
                    "dependency_type": "directive",
                    "extraction_confidence": "Low",
                    "validation_issue": "Requirements directive requires separate policy handling",
                    "raw_requirement": logical_line,
                    "is_exact_pin": False,
                    "hashes": {},
                    "direct_reference": None,
                }
            )
            continue

        requirement_text, hashes = _split_hash_options(logical_line)

        try:
            req = Requirement(requirement_text)
            exact_version = _exact_pin(req)
            direct_reference = req.url
            issues: list[str] = []

            if exact_version is None:
                issues.append("Missing immutable exact version pin")
            if direct_reference is not None:
                issues.append("Direct URL or VCS reference requires explicit provenance approval")
            if strict_supply_chain and not hashes.get("sha256"):
                issues.append("Missing SHA-256 artifact hash")

            components.append(
                {
                    "asset_id": asset_id,
                    "component_name": req.name.lower(),
                    "version": exact_version,
                    "ecosystem": "PyPI",
                    "source_file": str(path_obj),
                    "source_line": line_no,
                    "dependency_type": "runtime",
                    "extraction_confidence": "High" if exact_version and not issues else "Medium",
                    "validation_issue": "; ".join(issues) if issues else None,
                    "raw_requirement": logical_line,
                    "raw_specifier": str(req.specifier),
                    "is_exact_pin": exact_version is not None,
                    "hashes": hashes,
                    "direct_reference": direct_reference,
                    "extras": sorted(req.extras),
                    "marker": str(req.marker) if req.marker is not None else None,
                }
            )

        except InvalidRequirement as exc:
            components.append(
                {
                    "asset_id": asset_id,
                    "component_name": requirement_text,
                    "version": None,
                    "ecosystem": "PyPI",
                    "source_file": str(path_obj),
                    "source_line": line_no,
                    "dependency_type": "unknown",
                    "extraction_confidence": "Low",
                    "validation_issue": f"Could not parse requirement: {exc}",
                    "raw_requirement": logical_line,
                    "is_exact_pin": False,
                    "hashes": hashes,
                    "direct_reference": None,
                }
            )

    return components
