import hashlib
import json
import re
from pathlib import Path
from typing import Dict, Any


CVE_PATTERN = re.compile(r"^CVE-\\d{4}-\\d{4,}$")


def sha256_file(path: str) -> str:
    file_path = Path(path)
    digest = hashlib.sha256()

    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)

    return digest.hexdigest()


def assign_trust_level(issue_count: int, critical_failure: bool = False) -> str:
    if critical_failure:
        return "Rejected"
    if issue_count == 0:
        return "High"
    if issue_count <= 2:
        return "Medium"
    return "Low"


def validate_asset_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    required = [
        "asset_id",
        "asset_name",
        "sector",
        "exposure",
        "criticality",
        "data_sensitivity",
        "authorization_status"
    ]

    issues = []

    for field in required:
        if not metadata.get(field):
            issues.append(f"Missing required field: {field}")

    authorized = str(metadata.get("authorization_status", "")).lower()
    if "authorized" not in authorized:
        issues.append("Authorization status is not clearly marked as authorized")

    trust_level = assign_trust_level(len(issues))

    return {
        "input_type": "asset_metadata",
        "validation_status": "Valid" if trust_level in ["High", "Medium"] else "Needs Review",
        "trust_level": trust_level,
        "issues": issues,
        "human_review_required": trust_level == "Low"
    }


def is_valid_cve_id(cve_id: str) -> bool:
    return isinstance(cve_id, str) and bool(CVE_PATTERN.match(cve_id))


def validate_epss_record(record: Dict[str, Any]) -> Dict[str, Any]:
    issues = []

    if not is_valid_cve_id(record.get("cve")):
        issues.append("Invalid CVE ID")

    try:
        epss = float(record.get("epss"))
        if not 0 <= epss <= 1:
            issues.append("EPSS score outside 0 to 1")
    except Exception:
        issues.append("Invalid EPSS score")

    try:
        percentile = float(record.get("percentile"))
        if not 0 <= percentile <= 1:
            issues.append("EPSS percentile outside 0 to 1")
    except Exception:
        issues.append("Invalid EPSS percentile")

    if not record.get("date"):
        issues.append("Missing EPSS date")

    trust_level = assign_trust_level(len(issues))

    return {
        "input_type": "epss_record",
        "validation_status": "Valid" if trust_level in ["High", "Medium"] else "Needs Review",
        "trust_level": trust_level,
        "issues": issues,
        "human_review_required": trust_level == "Low"
    }
