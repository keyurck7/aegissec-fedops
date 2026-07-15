from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.intelligence.canonical_intelligence import (
    verify_canonical_intelligence_bundle,
    write_canonical_intelligence_bundle,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Correlate verified OSV, NVD, CISA KEV, and FIRST EPSS evidence "
            "into a field-provenanced canonical vulnerability intelligence record."
        )
    )
    parser.add_argument("--summary", required=True)
    parser.add_argument("--target-cve", required=True)
    parser.add_argument(
        "--output-dir",
        default="data/processed/canonical_intelligence",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    paths = write_canonical_intelligence_bundle(
        summary_path=args.summary,
        target_cve=args.target_cve,
        output_dir=args.output_dir,
        project_root=PROJECT_ROOT,
    )
    canonical, report = verify_canonical_intelligence_bundle(paths.canonical_path)

    print("=" * 84)
    print("MILESTONE 12B CANONICAL INTELLIGENCE CORRELATION")
    print("=" * 84)
    print("Canonical record:", paths.canonical_path.relative_to(PROJECT_ROOT))
    print("Correlation report:", paths.correlation_path.relative_to(PROJECT_ROOT))
    print("Integrity manifest:", paths.integrity_path.relative_to(PROJECT_ROOT))
    print("Record ID:", canonical["record_id"])
    print("Target CVE:", canonical["target"]["cve_id"])
    print("Component:", json.dumps(canonical["target"]["component"], sort_keys=True))
    print("Exact source matches:", json.dumps(report["exact_target_matches"], sort_keys=True))
    print("Adjacent OSV records isolated:", len(report["adjacent_records"]))
    print("Package evidence:", canonical["package_evidence"]["aggregate_status"])
    print("CISA KEV:", canonical["exploitation"]["kev"]["status"])
    print("EPSS status:", canonical["exploitation"]["epss"]["status"])
    print("Conflicts:", len(report["conflicts"]))
    print("Assertion differences:", len(report["assertion_differences"]))
    print("Field provenance entries:", len(canonical["field_provenance"]))
    print("Stage gate:", report["release_decision"]["stage_gate"])
    print("Affectedness:", canonical["affectedness_decision"]["status"])
    print("Production readiness:", canonical["production_readiness"])
    print("Canonical intelligence correlation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
