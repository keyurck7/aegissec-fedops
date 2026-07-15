from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.affectedness.versioning import evaluate_version_range, parse_version
from src.intelligence.field_provenance import ProvenanceContext
from src.intelligence.official_source import (
    OfficialSourceIntegrityError,
    canonical_json_bytes,
    verify_official_source_bundle,
)


REQUIRED_SOURCES = ("OSV", "NVD", "CISA_KEV", "FIRST_EPSS")
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")

SOURCE_CLAIM_OWNERSHIP: dict[str, tuple[str, ...]] = {
    "NVD": ("cve_metadata", "cvss", "cwe", "ssvc"),
    "CISA_KEV": (
        "known_exploitation",
        "federal_due_date",
        "required_action",
        "ransomware_use",
    ),
    "FIRST_EPSS": ("exploit_probability", "percentile", "score_date"),
    "OSV": (
        "package_identity",
        "affected_ranges",
        "fixed_versions",
        "ecosystem_aliases",
    ),
}


class SourceCorrelationError(RuntimeError):
    """Raised when official evidence cannot be correlated without guessing."""


@dataclass(frozen=True)
class VerifiedSource:
    source_name: str
    envelope_path: Path
    payload_path: Path
    integrity_path: Path
    envelope: dict[str, Any]
    payload: Any

    @property
    def context(self) -> ProvenanceContext:
        record_ids = self.envelope["records"]["record_ids"]
        source_record_id = record_ids[0] if len(record_ids) == 1 else self.envelope["envelope_id"]
        return ProvenanceContext(
            source_name=self.source_name,
            source_record_id=source_record_id,
            source_authority=self.envelope["source"]["source_authority"],
            retrieved_at=self.envelope["retrieval"]["retrieved_at"],
            artifact_sha256=self.envelope["artifact"]["sha256"],
            envelope_id=self.envelope["envelope_id"],
        )


@dataclass(frozen=True)
class VerifiedOfficialRun:
    project_root: Path
    summary_path: Path
    summary: dict[str, Any]
    summary_sha256: str
    sources: Mapping[str, VerifiedSource]


def normalize_cve_id(value: str) -> str:
    normalized = str(value).strip().upper()
    if not CVE_PATTERN.fullmatch(normalized):
        raise ValueError(f"Invalid CVE identifier: {value!r}")
    return normalized


def _resolve_repo_path(project_root: Path, value: str | Path) -> Path:
    candidate = Path(value)
    resolved = candidate.resolve() if candidate.is_absolute() else (project_root / candidate).resolve()
    if resolved != project_root and project_root not in resolved.parents:
        raise SourceCorrelationError(f"Evidence path escapes repository root: {value}")
    return resolved


def _load_canonical_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SourceCorrelationError(f"Unable to read evidence artifact: {path}") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceCorrelationError(f"Malformed JSON evidence artifact: {path}") from exc
    if canonical_json_bytes(value) != raw and path.name != "milestone12_official_source_summary.json":
        raise SourceCorrelationError(f"Evidence artifact is not canonically serialized: {path}")
    return value


def load_verified_official_run(
    summary_path: Path | str,
    *,
    project_root: Path | str,
) -> VerifiedOfficialRun:
    root = Path(project_root).resolve()
    summary_file = _resolve_repo_path(root, summary_path)
    summary = _load_canonical_json(summary_file)
    if not isinstance(summary, dict):
        raise SourceCorrelationError("Official-source summary must be a JSON object.")
    if summary.get("schema_version") != "1.0.0":
        raise SourceCorrelationError("Unsupported official-source summary schema version.")
    if summary.get("network_used") is not True:
        raise SourceCorrelationError("Official-source summary must record live network use.")
    if summary.get("production_readiness") != "BLOCKED":
        raise SourceCorrelationError("Official-source summary removed the production blocker.")

    source_entries = summary.get("sources")
    if not isinstance(source_entries, dict):
        raise SourceCorrelationError("Official-source summary sources must be an object.")
    observed = set(source_entries)
    required = set(REQUIRED_SOURCES)
    if observed != required:
        raise SourceCorrelationError(
            "Official-source run must contain exactly the required source set; "
            f"missing={sorted(required - observed)}, unexpected={sorted(observed - required)}"
        )

    verified: dict[str, VerifiedSource] = {}
    for source_name in REQUIRED_SOURCES:
        item = source_entries[source_name]
        if not isinstance(item, dict):
            raise SourceCorrelationError(f"Summary source entry is malformed: {source_name}")
        envelope_path = _resolve_repo_path(root, item.get("envelope", ""))
        payload_path = _resolve_repo_path(root, item.get("payload", ""))
        integrity_path = _resolve_repo_path(root, item.get("integrity", ""))
        try:
            envelope = verify_official_source_bundle(envelope_path)
        except OfficialSourceIntegrityError as exc:
            raise SourceCorrelationError(
                f"Official-source bundle failed integrity verification: {source_name}"
            ) from exc
        if envelope["source"]["source_name"] != source_name:
            raise SourceCorrelationError(f"Source-name mismatch in envelope: {source_name}")
        expected_payload = envelope_path.parent / envelope["artifact"]["payload_filename"]
        expected_integrity = envelope_path.with_name(
            envelope_path.name.replace(".envelope.json", ".integrity.sha256")
        )
        if payload_path != expected_payload or integrity_path != expected_integrity:
            raise SourceCorrelationError(f"Summary artifact paths disagree with envelope: {source_name}")
        if sorted(item.get("record_ids", [])) != sorted(envelope["records"]["record_ids"]):
            raise SourceCorrelationError(f"Summary record IDs disagree with envelope: {source_name}")
        payload = _load_canonical_json(payload_path)
        verified[source_name] = VerifiedSource(
            source_name=source_name,
            envelope_path=envelope_path,
            payload_path=payload_path,
            integrity_path=integrity_path,
            envelope=envelope,
            payload=payload,
        )

    return VerifiedOfficialRun(
        project_root=root,
        summary_path=summary_file,
        summary=summary,
        summary_sha256=hashlib.sha256(summary_file.read_bytes()).hexdigest(),
        sources=verified,
    )


def _as_object(value: Any, message: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SourceCorrelationError(message)
    return value


def _as_list(value: Any, message: str) -> list[Any]:
    if not isinstance(value, list):
        raise SourceCorrelationError(message)
    return value


def _english_description(descriptions: Any) -> str | None:
    if not isinstance(descriptions, list):
        return None
    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en" and isinstance(item.get("value"), str):
            return item["value"]
    return None


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        try:
            day = date.fromisoformat(text)
        except ValueError:
            return None
        return datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _cvss_assertions(metrics: Any, target_cve: str) -> list[dict[str, Any]]:
    if not isinstance(metrics, dict):
        return []
    assertions: list[dict[str, Any]] = []
    for family in sorted(metrics):
        if not family.lower().startswith("cvssmetric"):
            continue
        values = metrics[family]
        if not isinstance(values, list):
            continue
        for index, item in enumerate(values):
            if not isinstance(item, dict) or not isinstance(item.get("cvssData"), dict):
                continue
            data = item["cvssData"]
            assertions.append(
                {
                    "metric_family": family,
                    "metric_index": index,
                    "version": str(data.get("version", "")),
                    "vector": data.get("vectorString"),
                    "base_score": data.get("baseScore"),
                    "base_severity": data.get("baseSeverity"),
                    "exploitability_score": item.get("exploitabilityScore"),
                    "impact_score": item.get("impactScore"),
                    "source": item.get("source"),
                    "type": item.get("type"),
                    "source_record_id": target_cve,
                }
            )
    return assertions


def _select_primary_cvss(assertions: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    if not assertions:
        return None
    version_rank = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}
    return sorted(
        assertions,
        key=lambda item: (
            item.get("type") == "Primary",
            str(item.get("source", "")).casefold() == "nvd@nist.gov",
            version_rank.get(str(item.get("version")), 0),
            float(item.get("base_score") or -1),
        ),
        reverse=True,
    )[0]


def extract_nvd_assertion(source: VerifiedSource, target_cve: str) -> dict[str, Any]:
    payload = _as_object(source.payload, "NVD payload must be an object.")
    rows = _as_list(payload.get("vulnerabilities"), "NVD vulnerabilities must be a list.")
    matches: list[tuple[int, dict[str, Any]]] = []
    for index, wrapper in enumerate(rows):
        if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
            raise SourceCorrelationError(f"Malformed NVD record at index {index}.")
        record = wrapper["cve"]
        if str(record.get("id", "")).upper() == target_cve:
            matches.append((index, record))
    if len(matches) > 1:
        raise SourceCorrelationError("NVD returned duplicate exact-target records.")
    if not matches:
        return {"exact_match_count": 0, "record": None, "record_index": None}
    index, record = matches[0]
    weaknesses: set[str] = set()
    for weakness in record.get("weaknesses", []) if isinstance(record.get("weaknesses"), list) else []:
        if not isinstance(weakness, dict):
            continue
        for item in weakness.get("description", []) if isinstance(weakness.get("description"), list) else []:
            value = item.get("value") if isinstance(item, dict) else None
            if isinstance(value, str) and value.upper().startswith("CWE-"):
                weaknesses.add(value.upper())
    cvss = _cvss_assertions(record.get("metrics"), target_cve)
    ssvc: list[dict[str, Any]] = []
    metrics = record.get("metrics")
    if isinstance(metrics, dict):
        for family in sorted(metrics):
            if not family.casefold().startswith("ssvc"):
                continue
            values = metrics[family]
            if isinstance(values, list):
                for metric_index, item in enumerate(values):
                    if isinstance(item, dict):
                        ssvc.append(
                            {
                                "metric_family": family,
                                "metric_index": metric_index,
                                "source": item.get("source"),
                                "data": item.get("ssvcData"),
                            }
                        )
    return {
        "exact_match_count": 1,
        "record_index": index,
        "record": {
            "cve_id": target_cve,
            "source_identifier": record.get("sourceIdentifier"),
            "status": record.get("vulnStatus"),
            "published_at": record.get("published"),
            "last_modified_at": record.get("lastModified"),
            "description": _english_description(record.get("descriptions")),
            "weaknesses": sorted(weaknesses),
            "cvss_assertions": cvss,
            "selected_cvss": _select_primary_cvss(cvss),
            "ssvc_assertions": ssvc,
        },
    }


def extract_cisa_kev_assertion(source: VerifiedSource, target_cve: str) -> dict[str, Any]:
    payload = _as_object(source.payload, "CISA KEV payload must be an object.")
    rows = _as_list(payload.get("vulnerabilities"), "CISA KEV vulnerabilities must be a list.")
    matches: list[tuple[int, dict[str, Any]]] = []
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            raise SourceCorrelationError(f"Malformed CISA KEV record at index {index}.")
        if str(item.get("cveID", "")).upper() == target_cve:
            matches.append((index, item))
    if len(matches) > 1:
        raise SourceCorrelationError("CISA KEV contains duplicate exact-target records.")
    catalog_timestamp = payload.get("dateReleased") or payload.get("catalogVersion")
    if not matches:
        return {
            "exact_match_count": 0,
            "record": None,
            "record_index": None,
            "catalog_timestamp": catalog_timestamp,
        }
    index, item = matches[0]
    return {
        "exact_match_count": 1,
        "record_index": index,
        "catalog_timestamp": catalog_timestamp,
        "record": {
            "cve_id": target_cve,
            "title": item.get("vulnerabilityName"),
            "vendor_project": item.get("vendorProject"),
            "product": item.get("product"),
            "short_description": item.get("shortDescription"),
            "date_added": item.get("dateAdded"),
            "due_date": item.get("dueDate"),
            "required_action": item.get("requiredAction"),
            "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
            "notes": item.get("notes"),
            "weaknesses": sorted(
                {
                    str(value).upper()
                    for value in item.get("cwes", [])
                    if isinstance(value, str) and value.upper().startswith("CWE-")
                }
            ),
        },
    }


def extract_epss_assertion(source: VerifiedSource, target_cve: str) -> dict[str, Any]:
    payload = _as_object(source.payload, "FIRST EPSS payload must be an object.")
    rows = _as_list(payload.get("data"), "FIRST EPSS data must be a list.")
    matches: list[tuple[int, dict[str, Any]]] = []
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            raise SourceCorrelationError(f"Malformed FIRST EPSS record at index {index}.")
        if str(item.get("cve", "")).upper() == target_cve:
            matches.append((index, item))
    if len(matches) > 1:
        raise SourceCorrelationError("FIRST EPSS contains duplicate exact-target records.")
    if not matches:
        return {
            "exact_match_count": 0,
            "record": {
                "status": "MISSING",
                "cve_id": target_cve,
                "probability": None,
                "percentile": None,
                "score_date": None,
            },
            "record_index": None,
        }
    index, item = matches[0]
    try:
        probability = float(item["epss"])
        percentile = float(item["percentile"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SourceCorrelationError("FIRST EPSS exact-target record is malformed.") from exc
    if not 0 <= probability <= 1 or not 0 <= percentile <= 1:
        raise SourceCorrelationError("FIRST EPSS values must be within [0, 1].")
    return {
        "exact_match_count": 1,
        "record_index": index,
        "record": {
            "status": "PRESENT",
            "cve_id": target_cve,
            "probability": probability,
            "percentile": percentile,
            "score_date": item.get("date"),
        },
    }


def _osv_range_segments(range_item: Mapping[str, Any]) -> list[dict[str, Any]]:
    events = range_item.get("events")
    if not isinstance(events, list):
        return []
    range_type = str(range_item.get("type", "")).upper()
    introduced: str | None = None
    segments: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            introduced = str(event["introduced"])
        if "fixed" in event:
            segments.append(
                {
                    "range_type": range_type,
                    "introduced": introduced,
                    "fixed": str(event["fixed"]),
                    "last_affected": None,
                }
            )
            introduced = None
        if "last_affected" in event:
            segments.append(
                {
                    "range_type": range_type,
                    "introduced": introduced,
                    "fixed": None,
                    "last_affected": str(event["last_affected"]),
                }
            )
            introduced = None
    if introduced is not None:
        segments.append(
            {
                "range_type": range_type,
                "introduced": introduced,
                "fixed": None,
                "last_affected": None,
            }
        )
    return segments


def _evaluate_osv_package_entry(entry: Mapping[str, Any], component_version: str) -> dict[str, Any]:
    versions = entry.get("versions") if isinstance(entry.get("versions"), list) else []
    explicit_match = component_version in {str(value) for value in versions}
    parsed_component = parse_version(component_version)
    evaluations: list[dict[str, Any]] = []
    fixed_versions: set[str] = set()
    for range_index, item in enumerate(entry.get("ranges", []) if isinstance(entry.get("ranges"), list) else []):
        if not isinstance(item, dict):
            continue
        segments = _osv_range_segments(item)
        for segment_index, segment in enumerate(segments):
            fixed = segment.get("fixed")
            if isinstance(fixed, str):
                fixed_versions.add(fixed)
            if parsed_component is None:
                evaluations.append(
                    {
                        "range_index": range_index,
                        "segment_index": segment_index,
                        **segment,
                        "valid": False,
                        "affected": None,
                        "reason_codes": ["INVALID_COMPONENT_VERSION"],
                        "error": "Component version could not be parsed without guessing.",
                    }
                )
                continue
            result = evaluate_version_range(
                parsed_component,
                segment,
                segment_index,
                {"ECOSYSTEM", "SEMVER"},
            ).to_dict()
            result["range_index"] = range_index
            result["segment_index"] = segment_index
            evaluations.append(result)
    supported = explicit_match or any(item.get("affected") is True for item in evaluations)
    valid_evaluations = [item for item in evaluations if item.get("valid") is True]
    if supported:
        evidence_status = "AFFECTED_SUPPORTED"
    elif valid_evaluations and all(item.get("affected") is False for item in valid_evaluations):
        evidence_status = "NOT_AFFECTED_SUPPORTED"
    else:
        evidence_status = "SOURCE_QUERY_MATCH_ONLY"
    package = entry.get("package") if isinstance(entry.get("package"), dict) else {}
    return {
        "ecosystem": package.get("ecosystem"),
        "package_name": package.get("name"),
        "purl": package.get("purl"),
        "explicit_version_match": explicit_match,
        "range_evaluations": evaluations,
        "fixed_versions": sorted(fixed_versions),
        "evidence_status": evidence_status,
    }


def extract_osv_assertion(
    source: VerifiedSource,
    target_cve: str,
    *,
    package_name: str,
    ecosystem: str,
    version: str,
) -> dict[str, Any]:
    payload = _as_object(source.payload, "OSV payload must be an object.")
    rows = payload.get("vulns", [])
    rows = _as_list(rows, "OSV vulns must be a list.")
    exact: list[dict[str, Any]] = []
    adjacent: list[dict[str, Any]] = []
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            raise SourceCorrelationError(f"Malformed OSV record at index {index}.")
        record_id = str(item.get("id", ""))
        aliases = sorted({str(value).upper() for value in item.get("aliases", []) if isinstance(value, str)})
        identifiers = {record_id.upper(), *aliases}
        compact = {
            "record_index": index,
            "record_id": record_id,
            "aliases": aliases,
            "summary": item.get("summary"),
            "published_at": item.get("published"),
            "last_modified_at": item.get("modified"),
        }
        if target_cve in identifiers:
            package_assertions: list[dict[str, Any]] = []
            for affected_index, affected in enumerate(
                item.get("affected", []) if isinstance(item.get("affected"), list) else []
            ):
                if not isinstance(affected, dict):
                    continue
                package = affected.get("package") if isinstance(affected.get("package"), dict) else {}
                if (
                    str(package.get("name", "")).casefold() == package_name.casefold()
                    and str(package.get("ecosystem", "")).casefold() == ecosystem.casefold()
                ):
                    package_assertion = _evaluate_osv_package_entry(affected, version)
                    package_assertion["affected_index"] = affected_index
                    package_assertion["source_record_id"] = record_id
                    package_assertions.append(package_assertion)
            severity_label = None
            database_specific = item.get("database_specific")
            if isinstance(database_specific, dict) and isinstance(database_specific.get("severity"), str):
                severity_label = database_specific["severity"].upper()
            exact.append(
                {
                    **compact,
                    "severity_label": severity_label,
                    "weaknesses": sorted(
                        {
                            str(value).upper()
                            for value in (
                                database_specific.get("cwe_ids", [])
                                if isinstance(database_specific, dict)
                                and isinstance(database_specific.get("cwe_ids"), list)
                                else []
                            )
                            if isinstance(value, str) and value.upper().startswith("CWE-")
                        }
                    ),
                    "package_assertions": package_assertions,
                    "references": [
                        value.get("url")
                        for value in item.get("references", [])
                        if isinstance(value, dict) and isinstance(value.get("url"), str)
                    ],
                }
            )
        else:
            adjacent.append(
                {
                    **compact,
                    "reason": "COMPONENT_VERSION_MATCH_WITHOUT_TARGET_CVE_ALIAS",
                }
            )
    package_assertions = [
        assertion
        for record in exact
        for assertion in record["package_assertions"]
    ]
    if any(item["evidence_status"] == "AFFECTED_SUPPORTED" for item in package_assertions):
        aggregate_status = "AFFECTED_SUPPORTED"
    elif package_assertions and all(
        item["evidence_status"] == "NOT_AFFECTED_SUPPORTED" for item in package_assertions
    ):
        aggregate_status = "NOT_AFFECTED_SUPPORTED"
    elif exact:
        aggregate_status = "SOURCE_QUERY_MATCH_ONLY"
    else:
        aggregate_status = "NO_EXACT_TARGET_MATCH"
    return {
        "exact_match_count": len(exact),
        "exact_records": exact,
        "adjacent_records": adjacent,
        "package_evidence": {
            "source": "OSV",
            "exact_target_record_ids": sorted(item["record_id"] for item in exact),
            "assertions": package_assertions,
            "aggregate_status": aggregate_status,
        },
    }


def correlate_official_run(run: VerifiedOfficialRun, target_cve: str) -> dict[str, Any]:
    target = normalize_cve_id(target_cve)
    requested = {
        normalize_cve_id(value)
        for value in run.summary.get("requested_cve_ids", [])
    }
    if target not in requested:
        raise SourceCorrelationError(
            f"Target CVE {target} was not requested by the source run."
        )
    component = run.summary.get("component")
    if not isinstance(component, dict):
        raise SourceCorrelationError("Official-source summary component is malformed.")
    package_name = str(component.get("package_name", "")).strip()
    ecosystem = str(component.get("ecosystem", "")).strip()
    version = str(component.get("version", "")).strip()
    if not package_name or not ecosystem or not version:
        raise SourceCorrelationError("Component identity is incomplete.")

    nvd = extract_nvd_assertion(run.sources["NVD"], target)
    kev = extract_cisa_kev_assertion(run.sources["CISA_KEV"], target)
    epss = extract_epss_assertion(run.sources["FIRST_EPSS"], target)
    osv = extract_osv_assertion(
        run.sources["OSV"],
        target,
        package_name=package_name,
        ecosystem=ecosystem,
        version=version,
    )

    exact_matches = {
        "OSV": sorted(item["record_id"] for item in osv["exact_records"]),
        "NVD": [target] if nvd["exact_match_count"] else [],
        "CISA_KEV": [target] if kev["exact_match_count"] else [],
        "FIRST_EPSS": [target] if epss["exact_match_count"] else [],
    }
    source_inventory = []
    for source_name in REQUIRED_SOURCES:
        source = run.sources[source_name]
        source_inventory.append(
            {
                "source_name": source_name,
                "source_authority": source.envelope["source"]["source_authority"],
                "source_category": source.envelope["source"]["source_category"],
                "envelope_id": source.envelope["envelope_id"],
                "payload_sha256": source.envelope["artifact"]["sha256"],
                "retrieved_at": source.envelope["retrieval"]["retrieved_at"],
                "validation_status": source.envelope["validation"]["status"],
                "all_record_ids": source.envelope["records"]["record_ids"],
                "exact_target_record_ids": exact_matches[source_name],
                "claim_ownership": list(SOURCE_CLAIM_OWNERSHIP[source_name]),
                "artifact_paths": {
                    "envelope": str(source.envelope_path.relative_to(run.project_root)),
                    "payload": str(source.payload_path.relative_to(run.project_root)),
                    "integrity": str(source.integrity_path.relative_to(run.project_root)),
                },
            }
        )

    assertion_differences: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    nvd_record = nvd.get("record") or {}
    selected_cvss = nvd_record.get("selected_cvss") if isinstance(nvd_record, dict) else None
    nvd_severity = selected_cvss.get("base_severity") if isinstance(selected_cvss, dict) else None
    osv_severities = sorted(
        {
            item["severity_label"]
            for item in osv["exact_records"]
            if isinstance(item.get("severity_label"), str)
        }
    )
    if nvd_severity and osv_severities and str(nvd_severity).upper() not in osv_severities:
        conflicts.append(
            {
                "field": "/vulnerability/severity/selected/base_severity",
                "classification": "SEVERITY_LABEL_MISMATCH",
                "blocking": False,
                "assertions": {
                    "NVD": str(nvd_severity).upper(),
                    "OSV": osv_severities,
                },
                "disposition": "PRESERVE_BOTH_REVIEW_REQUIRED",
            }
        )

    cwe_sets = {
        "NVD": set(nvd_record.get("weaknesses", [])) if isinstance(nvd_record, dict) else set(),
        "CISA_KEV": set((kev.get("record") or {}).get("weaknesses", [])),
        "OSV": {
            value
            for item in osv["exact_records"]
            for value in item.get("weaknesses", [])
        },
    }
    if len({tuple(sorted(values)) for values in cwe_sets.values() if values}) > 1:
        assertion_differences.append(
            {
                "field": "/vulnerability/weaknesses",
                "classification": "SOURCE_COVERAGE_DIFFERENCE",
                "blocking": False,
                "assertions": {key: sorted(value) for key, value in cwe_sets.items()},
                "disposition": "UNION_WITH_FIELD_LEVEL_PROVENANCE",
            }
        )

    return {
        "target_cve": target,
        "component": {
            "package_name": package_name,
            "ecosystem": ecosystem,
            "version": version,
        },
        "source_inventory": source_inventory,
        "exact_target_matches": exact_matches,
        "nvd": nvd,
        "cisa_kev": kev,
        "first_epss": epss,
        "osv": osv,
        "conflicts": conflicts,
        "assertion_differences": assertion_differences,
        "controls": {
            "exact_target_correlation_required": True,
            "source_count_is_consensus": False,
            "consensus_inference_permitted": False,
            "adjacent_record_isolation": True,
            "missing_numeric_values_coerced_to_zero": False,
        },
    }
