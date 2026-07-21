#!/usr/bin/env python3
"""Generate one governed request per unique component-CVE finding."""

from __future__ import annotations

import json
import sys

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )

from src.orchestration.finding_assessment_request import (  # noqa: E402
    build_requests_from_workbench,
    verify_finding_assessment_request,
    write_manifest_atomic,
)
from src.presentation_demo.unified_scan_workbench import (  # noqa: E402
    run_unified_scan,
)


SBOM = (
    ROOT
    / "data"
    / "demo"
    / "aegissec_demo_project.cdx.json"
)

ASSET = (
    ROOT
    / "data"
    / "sample_inputs"
    / "assets"
    / "valid_healthcare_asset.json"
)

OUTPUT = (
    ROOT
    / "reports"
    / "orchestration"
    / "m13b2b_finding_assessment_requests.json"
)


def main() -> int:
    print("=" * 76)
    print(
        "MILESTONE 13B.2B "
        "FINDING ASSESSMENT REQUESTS"
    )
    print("=" * 76)

    workbench = run_unified_scan(
        SBOM.read_bytes(),
        filename=SBOM.name,
        authorized=True,
    )

    asset_context = json.loads(
        ASSET.read_text(
            encoding="utf-8"
        )
    )

    manifest = build_requests_from_workbench(
        workbench_result=workbench,
        asset_context=asset_context,
    )

    for request in manifest[
        "requests"
    ]:
        if not (
            verify_finding_assessment_request(
                request
            )
        ):
            raise RuntimeError(
                "Request integrity failed: "
                + request["request_id"]
            )

    path, sidecar = (
        write_manifest_atomic(
            manifest,
            OUTPUT,
        )
    )

    statistics = manifest[
        "statistics"
    ]

    print(
        "Input ID            :",
        manifest["input_id"],
    )

    print(
        "Asset ID            :",
        manifest["asset_id"],
    )

    print(
        "Source finding rows :",
        statistics[
            "source_finding_rows"
        ],
    )

    print(
        "Unique requests     :",
        statistics[
            "request_count"
        ],
    )

    print(
        "Ready requests      :",
        statistics[
            "ready_count"
        ],
    )

    print(
        "Blocked requests    :",
        statistics[
            "blocked_count"
        ],
    )

    print(
        "Duplicate requests  :",
        statistics[
            "duplicate_request_count"
        ],
    )

    print(
        "Unique components   :",
        statistics[
            "unique_component_count"
        ],
    )

    print(
        "Unique CVEs         :",
        statistics[
            "unique_cve_count"
        ],
    )

    log4shell = [
        request
        for request
        in manifest["requests"]
        if request[
            "unit_of_assessment"
        ]["cve_id"]
        == "CVE-2021-44228"
        and "log4j"
        in str(
            request[
                "unit_of_assessment"
            ]["component"].get(
                "name"
            )
        ).lower()
    ]

    print()
    print(
        "Log4Shell requests  :",
        len(log4shell),
    )

    for request in log4shell:
        unit = request[
            "unit_of_assessment"
        ]

        print(
            "  ",
            request["request_id"],
            "|",
            unit["component"].get(
                "name"
            ),
            unit["component"].get(
                "version"
            ),
            "|",
            request["status"],
        )

    assert log4shell

    assert any(
        request["status"]
        == "READY_FOR_AFFECTEDNESS"
        for request in log4shell
    )

    assert (
        manifest["governance"][
            "affectedness_authority"
        ]
        == "DETERMINISTIC_ENGINE"
    )

    assert (
        manifest["governance"][
            "final_disposition_authority"
        ]
        == "HUMAN"
    )

    assert (
        manifest["governance"][
            "production_readiness"
        ]
        == "BLOCKED"
    )

    print()
    print(
        "Manifest            :",
        path.relative_to(ROOT),
    )

    print(
        "Sidecar             :",
        sidecar.relative_to(ROOT),
    )

    print(
        "Manifest SHA-256    :",
        manifest["integrity"][
            "manifest_sha256"
        ],
    )

    print()
    print("=" * 76)
    print(
        "MILESTONE 13B.2B "
        "FINDING REQUEST BOUNDARY: PASS"
    )
    print(
        "ASSESSMENT UNIT: "
        "ASSET × COMPONENT VERSION × CVE × EVIDENCE SNAPSHOT"
    )
    print(
        "UNKNOWN CONTEXT: PRESERVED"
    )
    print(
        "AFFECTEDNESS AUTHORITY: DETERMINISTIC ENGINE"
    )
    print(
        "FINAL AUTHORITY: HUMAN"
    )
    print(
        "PRODUCTION READINESS: BLOCKED"
    )
    print("=" * 76)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
