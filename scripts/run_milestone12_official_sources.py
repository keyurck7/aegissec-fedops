from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.intelligence.cisa_kev_client import (
    find_cisa_kev_records,
    query_cisa_kev_catalog,
)
from src.intelligence.epss_client import epss_record_ids, query_epss_scores
from src.intelligence.nvd_client import nvd_record_ids, query_nvd_cves
from src.intelligence.official_source import write_official_source_bundle
from src.intelligence.osv_official_client import osv_record_ids, query_osv_component


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Retrieve OSV, NVD, CISA KEV, and FIRST EPSS evidence "
            "for the Milestone 12 operational vertical slice."
        )
    )
    parser.add_argument("--cve", action="append", required=True)
    parser.add_argument("--package-name", required=True)
    parser.add_argument("--ecosystem", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--output-dir",
        default="data/raw/official_sources",
    )
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--max-attempts", type=int, default=3)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = (PROJECT_ROOT / args.output_dir).resolve()
    if output_dir != PROJECT_ROOT and PROJECT_ROOT not in output_dir.parents:
        raise SystemExit("Output directory must remain within the repository.")
    retrieved_at = datetime.now(timezone.utc)
    common: dict[str, Any] = {
        "timeout_seconds": args.timeout_seconds,
        "max_attempts": args.max_attempts,
        "evaluated_at": retrieved_at,
    }

    osv = query_osv_component(
        package_name=args.package_name,
        ecosystem=args.ecosystem,
        version=args.version,
        **common,
    )
    nvd = query_nvd_cves(
        args.cve,
        api_key=os.getenv("NVD_API_KEY"),
        **common,
    )
    kev = query_cisa_kev_catalog(**common)
    epss = query_epss_scores(args.cve, **common)

    records = {
        "OSV": osv_record_ids(osv),
        "NVD": nvd_record_ids(nvd, requested_cve_ids=args.cve),
        "CISA_KEV": [
            str(item["cveID"])
            for item in find_cisa_kev_records(kev.payload, args.cve)
        ],
        "FIRST_EPSS": epss_record_ids(
            epss,
            requested_cve_ids=args.cve,
        ),
    }

    bundles = {}
    for result in (osv, nvd, kev, epss):
        paths = write_official_source_bundle(
            output_dir,
            result,
            source_record_ids=records[result.source_name],
            validation_status=(
                "accepted"
                if records[result.source_name]
                else "accepted_with_warnings"
            ),
            validation_warnings=(
                ()
                if records[result.source_name]
                else ("No requested source record was present.",)
            ),
        )
        bundles[result.source_name] = {
            "envelope": str(paths.envelope_path.relative_to(PROJECT_ROOT)),
            "payload": str(paths.payload_path.relative_to(PROJECT_ROOT)),
            "integrity": str(paths.integrity_path.relative_to(PROJECT_ROOT)),
            "record_ids": records[result.source_name],
        }

    summary = {
        "schema_version": "1.0.0",
        "run_id": "AEG-M12-OFFICIAL-" + retrieved_at.strftime("%Y%m%dT%H%M%SZ"),
        "retrieved_at": retrieved_at.isoformat(),
        "component": {
            "package_name": args.package_name,
            "ecosystem": args.ecosystem,
            "version": args.version,
        },
        "requested_cve_ids": sorted({value.upper() for value in args.cve}),
        "sources": bundles,
        "network_used": True,
        "production_readiness": "BLOCKED",
        "limitations": [
            "Official source retrieval alone does not prove affectedness.",
            "Production identity, independent review, and operational validation remain incomplete.",
        ],
    }
    summary_path = output_dir / "milestone12_official_source_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("=" * 84)
    print("MILESTONE 12 OFFICIAL SOURCE RETRIEVAL")
    print("=" * 84)
    for source_name, item in bundles.items():
        print(f"{source_name}: {len(item['record_ids'])} matching record(s)")
        print(f"  envelope: {item['envelope']}")
    print("Summary:", summary_path.relative_to(PROJECT_ROOT))
    print("Official source retrieval: PASS")
    print("Production readiness: BLOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
