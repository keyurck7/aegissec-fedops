#!/usr/bin/env python3
"""Run the controlled CycloneDX SBOM vulnerability scan."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )


from src.presentation_demo.sbom_ingestion import (  # noqa: E402
    scan_cyclonedx_bytes,
    serializable_scan,
)


SBOM_PATH = (
    ROOT
    / "data"
    / "demo"
    / "aegissec_demo_project.cdx.json"
)

OUTPUT_PATH = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "sbom_uploads"
    / "latest_sbom_scan.json"
)


def sha256_file(
    path: Path,
) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def main() -> int:
    if not SBOM_PATH.is_file():
        raise SystemExit(
            "Controlled CycloneDX "
            "SBOM is missing."
        )

    result = scan_cyclonedx_bytes(
        SBOM_PATH.read_bytes(),
        filename=SBOM_PATH.name,
    )

    serializable = serializable_scan(
        result
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT_PATH.write_text(
        json.dumps(
            serializable,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    digest = sha256_file(
        OUTPUT_PATH
    )

    sidecar = Path(
        f"{OUTPUT_PATH}.sha256"
    )

    sidecar.write_text(
        f"{digest}  "
        f"{OUTPUT_PATH.name}\n",
        encoding="utf-8",
    )

    print("=" * 78)
    print(
        "AEGISSEC-FEDOPS "
        "CYCLONEDX SBOM INGESTION"
    )
    print("=" * 78)

    print(
        json.dumps(
            result["summary"],
            indent=2,
            sort_keys=True,
        )
    )

    print()
    print(
        "Top matched components:"
    )

    matched = result[
        "matched_components"
    ]

    if matched.empty:
        print("  NONE")
    else:
        columns = [
            "component_id",
            "sector",
            "ecosystem",
            "package_name",
            "version",
            "vulnerability_count",
            "kev_count",
            "max_epss",
            "attention_score",
        ]

        print(
            matched[
                columns
            ]
            .sort_values(
                [
                    "kev_count",
                    "max_epss",
                    "attention_score",
                ],
                ascending=False,
            )
            .to_string(
                index=False
            )
        )

    print()
    print(
        "Report           :",
        OUTPUT_PATH,
    )

    print(
        "Report SHA-256   :",
        digest,
    )

    print(
        "SSVC authority   : PRESERVED"
    )

    print(
        "Clean bill       : PROHIBITED"
    )

    print(
        "Human review     : REQUIRED"
    )

    print(
        "Production       : BLOCKED"
    )

    print(
        "SBOM INGESTION   : PASS"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
