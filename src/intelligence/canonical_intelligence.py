from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from jsonschema import Draft202012Validator, FormatChecker

from src.governance.recovery_checkpoint import atomic_write_bundle
from src.intelligence.field_provenance import (
    ProvenanceContext,
    assert_provenance_coverage,
    build_field_provenance,
    stable_identifier,
)
from src.intelligence.official_source import canonical_json_bytes
from src.intelligence.source_correlation import (
    REQUIRED_SOURCES,
    VerifiedOfficialRun,
    correlate_official_run,
    load_verified_official_run,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CANONICAL_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_canonical_vulnerability_intelligence.schema.json"
)
DEFAULT_CORRELATION_SCHEMA = (
    PROJECT_ROOT / "schemas" / "aegis_source_correlation_report.schema.json"
)


class CanonicalIntelligenceError(RuntimeError):
    """Raised when a canonical intelligence record cannot be built safely."""


@dataclass(frozen=True)
class CanonicalIntelligenceBundlePaths:
    canonical_path: Path
    correlation_path: Path
    integrity_path: Path


def _load_schema(path: Path | str) -> dict[str, Any]:
    schema_path = Path(path)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def _validate(document: Mapping[str, Any], schema_path: Path | str, label: str) -> None:
    schema = _load_schema(schema_path)
    errors = sorted(
        Draft202012Validator(
            schema,
            format_checker=FormatChecker(),
        ).iter_errors(dict(document)),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        messages = []
        for error in errors:
            location = ".".join(str(part) for part in error.absolute_path)
            messages.append(f"{location or '<root>'}: {error.message}")
        raise CanonicalIntelligenceError(
            f"{label} schema validation failed: " + "; ".join(messages)
        )


def _parse_time(value: Any) -> datetime | None:
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


def _freshness_check(
    *,
    check_id: str,
    source_name: str,
    observed_at: Any,
    reference_time: datetime,
    max_age_days: float | None,
    required: bool,
    semantic: str,
) -> dict[str, Any]:
    observed = _parse_time(observed_at)
    if observed is None:
        return {
            "check_id": check_id,
            "source_name": source_name,
            "semantic": semantic,
            "observed_at": None,
            "age_days": None,
            "max_age_days": max_age_days,
            "required": required,
            "status": "MISSING" if required else "NOT_OBSERVED",
            "blocking": required,
        }
    age_days = max((reference_time - observed).total_seconds() / 86400.0, 0.0)
    if max_age_days is None:
        status = "OBSERVED"
        blocking = False
    elif age_days <= max_age_days:
        status = "CURRENT"
        blocking = False
    else:
        status = "STALE"
        blocking = required
    return {
        "check_id": check_id,
        "source_name": source_name,
        "semantic": semantic,
        "observed_at": observed.isoformat(),
        "age_days": round(age_days, 6),
        "max_age_days": max_age_days,
        "required": required,
        "status": status,
        "blocking": blocking,
    }


def _source_context(
    run: VerifiedOfficialRun,
    source_name: str,
    record_id: str | None,
) -> ProvenanceContext:
    source = run.sources[source_name]
    return ProvenanceContext(
        source_name=source_name,
        source_record_id=(record_id or source.envelope["envelope_id"]),
        source_authority=source.envelope["source"]["source_authority"],
        retrieved_at=source.envelope["retrieval"]["retrieved_at"],
        artifact_sha256=source.envelope["artifact"]["sha256"],
        envelope_id=source.envelope["envelope_id"],
    )


def _input_context(run: VerifiedOfficialRun) -> ProvenanceContext:
    return ProvenanceContext(
        source_name="RUN_INPUT",
        source_record_id=str(run.summary["run_id"]),
        source_authority="declared_input",
        retrieved_at=str(run.summary["retrieved_at"]),
        artifact_sha256=run.summary_sha256,
        envelope_id=None,
    )


def _provenance(
    *,
    field_path: str,
    value: Any,
    context: ProvenanceContext,
    source_pointer: str,
    extraction_method: str = "deterministic_field_extraction",
) -> dict[str, Any]:
    return build_field_provenance(
        field_path=field_path,
        value=value,
        context=context,
        source_pointer=source_pointer,
        extraction_method=extraction_method,
    )


def _quality_gate(
    gate_id: str,
    metric: str,
    observed: Any,
    expected: Any,
    passed: bool,
) -> dict[str, Any]:
    return {
        "gate_id": gate_id,
        "metric": metric,
        "observed": observed,
        "expected": expected,
        "pass": bool(passed),
    }


def build_canonical_intelligence(
    run: VerifiedOfficialRun,
    *,
    target_cve: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    correlation = correlate_official_run(run, target_cve)
    target = correlation["target_cve"]
    generated_at = str(run.summary["retrieved_at"])
    reference_time = _parse_time(generated_at)
    if reference_time is None:
        raise CanonicalIntelligenceError("Run retrieval timestamp is invalid.")

    nvd = correlation["nvd"]
    nvd_record = nvd.get("record") or {}
    kev = correlation["cisa_kev"]
    kev_record = kev.get("record") or {}
    epss_record = correlation["first_epss"]["record"]
    osv = correlation["osv"]
    exact_osv = osv["exact_records"]

    aliases = {target}
    for record in exact_osv:
        aliases.add(str(record["record_id"]).upper())
        aliases.update(str(value).upper() for value in record.get("aliases", []))
    aliases.discard(target)

    title = (
        kev_record.get("title")
        or (exact_osv[0].get("summary") if exact_osv else None)
        or target
    )
    description = (
        nvd_record.get("description")
        or kev_record.get("short_description")
        or (exact_osv[0].get("summary") if exact_osv else None)
    )

    weaknesses = sorted(
        {
            *nvd_record.get("weaknesses", []),
            *kev_record.get("weaknesses", []),
            *(
                value
                for record in exact_osv
                for value in record.get("weaknesses", [])
            ),
        }
    )

    cvss_assertions = [dict(item, source_name="NVD") for item in nvd_record.get("cvss_assertions", [])]
    for record in exact_osv:
        if record.get("severity_label"):
            cvss_assertions.append(
                {
                    "metric_family": "OSV_DATABASE_SPECIFIC",
                    "metric_index": record["record_index"],
                    "version": None,
                    "vector": None,
                    "base_score": None,
                    "base_severity": record["severity_label"],
                    "exploitability_score": None,
                    "impact_score": None,
                    "source": "OSV",
                    "type": "Advisory",
                    "source_record_id": record["record_id"],
                    "source_name": "OSV",
                }
            )
    selected_cvss = nvd_record.get("selected_cvss")
    selected = dict(selected_cvss, source_name="NVD") if isinstance(selected_cvss, dict) else None

    kev_status = "LISTED" if kev["exact_match_count"] else "NOT_LISTED"
    exploitation = {
        "kev": {
            "status": kev_status,
            "listed": bool(kev["exact_match_count"]),
            "date_added": kev_record.get("date_added"),
            "due_date": kev_record.get("due_date"),
            "known_ransomware_campaign_use": kev_record.get("known_ransomware_campaign_use"),
            "required_action": kev_record.get("required_action"),
            "vendor_project": kev_record.get("vendor_project"),
            "product": kev_record.get("product"),
        },
        "epss": epss_record,
        "ssvc_assertions": nvd_record.get("ssvc_assertions", []),
    }

    source_assertions = correlation["source_inventory"]
    record_identity = {
        "target_cve": target,
        "component": correlation["component"],
        "source_run_id": run.summary["run_id"],
        "source_payloads": {
            item["source_name"]: item["payload_sha256"]
            for item in source_assertions
        },
    }
    record_id = stable_identifier("AEG-CVI", record_identity)

    freshness_checks = []
    for source_name in REQUIRED_SOURCES:
        source = run.sources[source_name]
        freshness_checks.append(
            _freshness_check(
                check_id=f"RETRIEVAL-{source_name}",
                source_name=source_name,
                observed_at=source.envelope["retrieval"]["retrieved_at"],
                reference_time=reference_time,
                max_age_days=1.0,
                required=True,
                semantic="retrieval_time",
            )
        )
    freshness_checks.extend(
        [
            _freshness_check(
                check_id="CISA-KEV-CATALOG",
                source_name="CISA_KEV",
                observed_at=kev.get("catalog_timestamp"),
                reference_time=reference_time,
                max_age_days=3.0,
                required=True,
                semantic="catalog_release_time",
            ),
            _freshness_check(
                check_id="FIRST-EPSS-SCORE",
                source_name="FIRST_EPSS",
                observed_at=epss_record.get("score_date"),
                reference_time=reference_time,
                max_age_days=2.0,
                required=epss_record.get("status") == "PRESENT",
                semantic="score_date",
            ),
            _freshness_check(
                check_id="NVD-RECORD-MODIFIED",
                source_name="NVD",
                observed_at=nvd_record.get("last_modified_at"),
                reference_time=reference_time,
                max_age_days=None,
                required=False,
                semantic="record_last_modified_time",
            ),
        ]
    )
    for record in exact_osv:
        freshness_checks.append(
            _freshness_check(
                check_id=f"OSV-RECORD-{record['record_id']}",
                source_name="OSV",
                observed_at=record.get("last_modified_at"),
                reference_time=reference_time,
                max_age_days=None,
                required=False,
                semantic="advisory_last_modified_time",
            )
        )
    freshness_blockers = [item["check_id"] for item in freshness_checks if item["blocking"]]

    provenance: list[dict[str, Any]] = []
    input_context = _input_context(run)
    provenance.extend(
        [
            _provenance(
                field_path="/target/cve_id",
                value=target,
                context=input_context,
                source_pointer="/requested_cve_ids",
                extraction_method="validated_run_input",
            ),
            _provenance(
                field_path="/target/component",
                value=correlation["component"],
                context=input_context,
                source_pointer="/component",
                extraction_method="validated_run_input",
            ),
        ]
    )
    if nvd["exact_match_count"]:
        nvd_context = _source_context(run, "NVD", target)
        nvd_index = nvd["record_index"]
        provenance.extend(
            [
                _provenance(
                    field_path="/identifiers/primary_cve",
                    value=target,
                    context=nvd_context,
                    source_pointer=f"/vulnerabilities/{nvd_index}/cve/id",
                ),
                _provenance(
                    field_path="/vulnerability/description",
                    value=description,
                    context=nvd_context,
                    source_pointer=f"/vulnerabilities/{nvd_index}/cve/descriptions",
                ),
                _provenance(
                    field_path="/vulnerability/status",
                    value=nvd_record.get("status"),
                    context=nvd_context,
                    source_pointer=f"/vulnerabilities/{nvd_index}/cve/vulnStatus",
                ),
                _provenance(
                    field_path="/vulnerability/published_at",
                    value=nvd_record.get("published_at"),
                    context=nvd_context,
                    source_pointer=f"/vulnerabilities/{nvd_index}/cve/published",
                ),
                _provenance(
                    field_path="/vulnerability/last_modified_at",
                    value=nvd_record.get("last_modified_at"),
                    context=nvd_context,
                    source_pointer=f"/vulnerabilities/{nvd_index}/cve/lastModified",
                ),
            ]
        )
        if selected is not None:
            provenance.append(
                _provenance(
                    field_path="/vulnerability/severity/selected",
                    value=selected,
                    context=nvd_context,
                    source_pointer=f"/vulnerabilities/{nvd_index}/cve/metrics",
                    extraction_method="deterministic_primary_cvss_selection",
                )
            )
        provenance.append(
            _provenance(
                field_path="/vulnerability/weaknesses",
                value=weaknesses,
                context=nvd_context,
                source_pointer=f"/vulnerabilities/{nvd_index}/cve/weaknesses",
                extraction_method="multi_source_union_anchor",
            )
        )
    if kev["exact_match_count"] and kev_record.get("weaknesses"):
        provenance.append(
            _provenance(
                field_path="/vulnerability/weaknesses",
                value=kev_record["weaknesses"],
                context=_source_context(run, "CISA_KEV", target),
                source_pointer=f"/vulnerabilities/{kev['record_index']}/cwes",
                extraction_method="multi_source_union_contribution",
            )
        )
    for osv_record in exact_osv:
        if osv_record.get("weaknesses"):
            provenance.append(
                _provenance(
                    field_path="/vulnerability/weaknesses",
                    value=osv_record["weaknesses"],
                    context=_source_context(run, "OSV", osv_record["record_id"]),
                    source_pointer=f"/vulns/{osv_record['record_index']}/database_specific/cwe_ids",
                    extraction_method="multi_source_union_contribution",
                )
            )
    if kev["exact_match_count"]:
        kev_context = _source_context(run, "CISA_KEV", target)
        kev_index = kev["record_index"]
        provenance.extend(
            [
                _provenance(
                    field_path="/vulnerability/title",
                    value=title,
                    context=kev_context,
                    source_pointer=f"/vulnerabilities/{kev_index}/vulnerabilityName",
                ),
                _provenance(
                    field_path="/exploitation/kev",
                    value=exploitation["kev"],
                    context=kev_context,
                    source_pointer=f"/vulnerabilities/{kev_index}",
                ),
            ]
        )
    else:
        kev_context = _source_context(run, "CISA_KEV", None)
        provenance.append(
            _provenance(
                field_path="/exploitation/kev",
                value=exploitation["kev"],
                context=kev_context,
                source_pointer="/vulnerabilities",
                extraction_method="explicit_absence_preservation",
            )
        )
        if exact_osv:
            osv_record = exact_osv[0]
            osv_context = _source_context(run, "OSV", osv_record["record_id"])
            provenance.append(
                _provenance(
                    field_path="/vulnerability/title",
                    value=title,
                    context=osv_context,
                    source_pointer=f"/vulns/{osv_record['record_index']}/summary",
                    extraction_method="fallback_title_selection",
                )
            )
        else:
            provenance.append(
                _provenance(
                    field_path="/vulnerability/title",
                    value=title,
                    context=input_context,
                    source_pointer="/requested_cve_ids",
                    extraction_method="target_identifier_fallback",
                )
            )
    epss_context = _source_context(
        run,
        "FIRST_EPSS",
        target if correlation["first_epss"]["exact_match_count"] else None,
    )
    epss_pointer = (
        f"/data/{correlation['first_epss']['record_index']}"
        if correlation["first_epss"]["record_index"] is not None
        else "/data"
    )
    provenance.append(
        _provenance(
            field_path="/exploitation/epss",
            value=epss_record,
            context=epss_context,
            source_pointer=epss_pointer,
            extraction_method=(
                "exact_cve_extraction"
                if epss_record["status"] == "PRESENT"
                else "explicit_missing_value_preservation"
            ),
        )
    )
    if exact_osv:
        for record in exact_osv:
            osv_context = _source_context(run, "OSV", record["record_id"])
            provenance.append(
                _provenance(
                    field_path="/package_evidence",
                    value=osv["package_evidence"],
                    context=osv_context,
                    source_pointer=f"/vulns/{record['record_index']}/affected",
                    extraction_method="exact_cve_alias_and_component_identity_filter",
                )
            )
    else:
        osv_context = _source_context(run, "OSV", None)
        provenance.append(
            _provenance(
                field_path="/package_evidence",
                value=osv["package_evidence"],
                context=osv_context,
                source_pointer="/vulns",
                extraction_method="explicit_no_exact_target_match",
            )
        )
    provenance.append(
        _provenance(
            field_path="/identifiers/aliases",
            value=sorted(aliases),
            context=(
                _source_context(run, "OSV", exact_osv[0]["record_id"])
                if exact_osv
                else input_context
            ),
            source_pointer=(f"/vulns/{exact_osv[0]['record_index']}" if exact_osv else "/requested_cve_ids"),
            extraction_method="exact_target_identifier_union",
        )
    )

    quality_gates = [
        _quality_gate(
            "M12B-SOURCE-SET",
            "required_source_bundle_count",
            len(source_assertions),
            len(REQUIRED_SOURCES),
            len(source_assertions) == len(REQUIRED_SOURCES),
        ),
        _quality_gate(
            "M12B-NVD-EXACT",
            "nvd_exact_target_count",
            nvd["exact_match_count"],
            1,
            nvd["exact_match_count"] == 1,
        ),
        _quality_gate(
            "M12B-CARDINALITY",
            "single_record_source_cardinality",
            {
                "NVD": nvd["exact_match_count"],
                "CISA_KEV": kev["exact_match_count"],
                "FIRST_EPSS": correlation["first_epss"]["exact_match_count"],
            },
            "each <= 1",
            all(
                value <= 1
                for value in (
                    nvd["exact_match_count"],
                    kev["exact_match_count"],
                    correlation["first_epss"]["exact_match_count"],
                )
            ),
        ),
        _quality_gate(
            "M12B-ADJACENT-ISOLATION",
            "adjacent_records_excluded_from_target_assertions",
            correlation["controls"]["adjacent_record_isolation"],
            True,
            correlation["controls"]["adjacent_record_isolation"] is True,
        ),
        _quality_gate(
            "M12B-NO-CONSENSUS-COUNTING",
            "source_count_interpreted_as_consensus",
            correlation["controls"]["source_count_is_consensus"],
            False,
            correlation["controls"]["source_count_is_consensus"] is False,
        ),
        _quality_gate(
            "M12B-MISSING-NOT-ZERO",
            "missing_numeric_values_coerced_to_zero",
            correlation["controls"]["missing_numeric_values_coerced_to_zero"],
            False,
            correlation["controls"]["missing_numeric_values_coerced_to_zero"] is False,
        ),
        _quality_gate(
            "M12B-FRESHNESS",
            "blocking_freshness_findings",
            freshness_blockers,
            [],
            not freshness_blockers,
        ),
        _quality_gate(
            "M12B-PRODUCTION-BLOCK",
            "production_readiness",
            "BLOCKED",
            "BLOCKED",
            True,
        ),
    ]

    record = {
        "schema_version": "1.0.0",
        "record_id": record_id,
        "generated_at": generated_at,
        "target": {
            "cve_id": target,
            "component": correlation["component"],
        },
        "source_run": {
            "run_id": run.summary["run_id"],
            "retrieved_at": run.summary["retrieved_at"],
            "summary_path": str(run.summary_path.relative_to(run.project_root)),
            "summary_sha256": run.summary_sha256,
            "network_used": True,
        },
        "identifiers": {
            "primary_cve": target,
            "aliases": sorted(aliases),
        },
        "vulnerability": {
            "title": title,
            "description": description,
            "status": nvd_record.get("status"),
            "published_at": nvd_record.get("published_at"),
            "last_modified_at": nvd_record.get("last_modified_at"),
            "weaknesses": weaknesses,
            "severity": {
                "selected": selected,
                "assertions": cvss_assertions,
            },
        },
        "exploitation": exploitation,
        "package_evidence": osv["package_evidence"],
        "source_assertions": source_assertions,
        "adjacent_vulnerabilities": osv["adjacent_records"],
        "field_provenance": provenance,
        "correlation_controls": {
            **correlation["controls"],
            "exact_target_matches": correlation["exact_target_matches"],
            "conflicts": correlation["conflicts"],
            "assertion_differences": correlation["assertion_differences"],
        },
        "freshness": {
            "reference_time": reference_time.isoformat(),
            "checks": freshness_checks,
            "blocking_findings": freshness_blockers,
        },
        "quality": {
            "source_bundle_verification": "PASS",
            "quality_gates": quality_gates,
            "warnings": [
                "CISA KEV absence would mean not listed, not not exploitable."
                if kev_status == "NOT_LISTED"
                else "",
                "FIRST EPSS missing values remain null and require explicit handling."
                if epss_record["status"] == "MISSING"
                else "",
            ],
            "limitations": [
                "Canonical correlation does not prove runtime reachability or deployed affectedness.",
                "OSV package-version results may include adjacent CVEs and are isolated by exact identifiers.",
                "NVD CPE configurations are not direct proof of the observed package instance.",
                "EPSS is a probability estimate, not evidence of active exploitation on an asset.",
                "CISA KEV listing applies to the vulnerability, not proof that this component instance is affected.",
                "Independent security review and real operational validation remain incomplete.",
            ],
        },
        "affectedness_decision": {
            "status": "NOT_EVALUATED",
            "reason": (
                "Milestone 12B prepares source-governed evidence. "
                "Affectedness must be adjudicated in the next controlled stage."
            ),
        },
        "production_readiness": "BLOCKED",
    }
    record["quality"]["warnings"] = [value for value in record["quality"]["warnings"] if value]

    required_provenance = {
        "/target/cve_id",
        "/target/component",
        "/identifiers/primary_cve",
        "/identifiers/aliases",
        "/vulnerability/title",
        "/vulnerability/description",
        "/vulnerability/status",
        "/vulnerability/published_at",
        "/vulnerability/last_modified_at",
        "/vulnerability/weaknesses",
        "/exploitation/kev",
        "/exploitation/epss",
        "/package_evidence",
    }
    if selected is not None:
        required_provenance.add("/vulnerability/severity/selected")
    assert_provenance_coverage(record, required_field_paths=required_provenance)

    stage_gate_pass = all(item["pass"] for item in quality_gates)
    report_identity = {
        "canonical_record_id": record_id,
        "source_run_id": run.summary["run_id"],
        "exact_target_matches": correlation["exact_target_matches"],
    }
    report_id = stable_identifier("AEG-SCR", report_identity)
    report = {
        "schema_version": "1.0.0",
        "report_id": report_id,
        "generated_at": generated_at,
        "target": record["target"],
        "source_run": record["source_run"],
        "source_inventory": source_assertions,
        "exact_target_matches": correlation["exact_target_matches"],
        "adjacent_records": osv["adjacent_records"],
        "controls": correlation["controls"],
        "conflicts": correlation["conflicts"],
        "assertion_differences": correlation["assertion_differences"],
        "freshness": record["freshness"],
        "quality_gates": quality_gates,
        "canonical_record": {
            "record_id": record_id,
            "filename": None,
            "sha256": None,
        },
        "release_decision": {
            "stage_gate": "PASS" if stage_gate_pass else "FAIL",
            "production_readiness": "BLOCKED",
            "blocking_reasons": [
                "Real operational validation has not yet been completed.",
                "Independent security review has not yet been completed.",
                "Affectedness and runtime reachability have not yet been adjudicated.",
            ],
        },
        "limitations": record["quality"]["limitations"],
    }
    return record, report


def write_canonical_intelligence_bundle(
    *,
    summary_path: Path | str,
    target_cve: str,
    output_dir: Path | str,
    project_root: Path | str = PROJECT_ROOT,
    canonical_schema_path: Path | str = DEFAULT_CANONICAL_SCHEMA,
    correlation_schema_path: Path | str = DEFAULT_CORRELATION_SCHEMA,
) -> CanonicalIntelligenceBundlePaths:
    root = Path(project_root).resolve()
    output = Path(output_dir)
    output = output.resolve() if output.is_absolute() else (root / output).resolve()
    if output != root and root not in output.parents:
        raise CanonicalIntelligenceError("Output directory must remain within the repository.")
    run = load_verified_official_run(summary_path, project_root=root)
    record, report = build_canonical_intelligence(run, target_cve=target_cve)

    canonical_name = record["record_id"].casefold() + ".canonical.json"
    correlation_name = report["report_id"].casefold() + ".correlation.json"
    integrity_name = record["record_id"].casefold() + ".integrity.sha256"
    canonical_path = output / canonical_name
    correlation_path = output / correlation_name
    integrity_path = output / integrity_name

    report["canonical_record"]["filename"] = canonical_name
    canonical_bytes = canonical_json_bytes(record)
    report["canonical_record"]["sha256"] = hashlib.sha256(canonical_bytes).hexdigest()
    report_bytes = canonical_json_bytes(report)

    _validate(record, canonical_schema_path, "Canonical intelligence record")
    _validate(report, correlation_schema_path, "Source correlation report")

    manifest_bytes = (
        f"{hashlib.sha256(canonical_bytes).hexdigest()}  {canonical_name}\n"
        f"{hashlib.sha256(report_bytes).hexdigest()}  {correlation_name}\n"
    ).encode("utf-8")
    atomic_write_bundle(
        {
            canonical_path: canonical_bytes,
            correlation_path: report_bytes,
            integrity_path: manifest_bytes,
        }
    )
    return CanonicalIntelligenceBundlePaths(
        canonical_path=canonical_path,
        correlation_path=correlation_path,
        integrity_path=integrity_path,
    )


def verify_canonical_intelligence_bundle(
    canonical_path: Path | str,
    *,
    canonical_schema_path: Path | str = DEFAULT_CANONICAL_SCHEMA,
    correlation_schema_path: Path | str = DEFAULT_CORRELATION_SCHEMA,
) -> tuple[dict[str, Any], dict[str, Any]]:
    canonical_file = Path(canonical_path)
    try:
        canonical = json.loads(canonical_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CanonicalIntelligenceError("Canonical intelligence record is unreadable.") from exc
    _validate(canonical, canonical_schema_path, "Canonical intelligence record")
    record_id = canonical["record_id"].casefold()
    candidates = sorted(canonical_file.parent.glob("aeg-scr-*.correlation.json"))
    matching: list[tuple[Path, dict[str, Any]]] = []
    canonical_hash = hashlib.sha256(canonical_file.read_bytes()).hexdigest()
    for path in candidates:
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if (
            report.get("canonical_record", {}).get("record_id") == canonical["record_id"]
            and report.get("canonical_record", {}).get("sha256") == canonical_hash
        ):
            matching.append((path, report))
    if len(matching) != 1:
        raise CanonicalIntelligenceError(
            "Expected exactly one matching source correlation report."
        )
    report_path, report = matching[0]
    _validate(report, correlation_schema_path, "Source correlation report")
    integrity_path = canonical_file.parent / f"{record_id}.integrity.sha256"
    if not integrity_path.is_file():
        raise CanonicalIntelligenceError("Canonical intelligence integrity manifest is missing.")
    entries = {
        line.split(maxsplit=1)[1].strip(): line.split(maxsplit=1)[0]
        for line in integrity_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    for path in (canonical_file, report_path):
        if entries.get(path.name) != hashlib.sha256(path.read_bytes()).hexdigest():
            raise CanonicalIntelligenceError(f"Derived intelligence integrity mismatch: {path.name}")
    if canonical_json_bytes(canonical) != canonical_file.read_bytes():
        raise CanonicalIntelligenceError("Canonical intelligence record is not canonical JSON.")
    if canonical_json_bytes(report) != report_path.read_bytes():
        raise CanonicalIntelligenceError("Source correlation report is not canonical JSON.")
    return canonical, report
