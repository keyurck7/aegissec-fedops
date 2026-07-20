"""Build a real EPSS and CISA KEV benchmark dataset."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import pandas as pd


EPSS_URL_TEMPLATE = (
    "https://epss.empiricalsecurity.com/"
    "epss_scores-{score_date}.csv.gz"
)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

ROOT = Path(__file__).resolve().parents[2]

DEFAULT_CACHE_DIR = (
    ROOT
    / "data"
    / "cache"
    / "presentation_demo"
)

DEFAULT_OUTPUT_DIR = (
    ROOT
    / "data"
    / "processed"
    / "presentation_demo"
    / "model_benchmark"
)


class RealBenchmarkDataError(RuntimeError):
    """Raised when real benchmark data fails validation."""


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def write_sidecar(path: Path) -> Path:
    sidecar = Path(f"{path}.sha256")

    sidecar.write_text(
        f"{sha256_file(path)}  {path.name}\n",
        encoding="utf-8",
    )

    return sidecar


def download_bytes(
    url: str,
    *,
    timeout: float = 60.0,
    attempts: int = 3,
) -> bytes:
    headers = {
        "Accept": "*/*",
        "User-Agent": (
            "AegisSec-FedOps/1.0 "
            "academic-controlled-benchmark"
        ),
    }

    last_error: Exception | None = None

    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            url,
            headers=headers,
            method="GET",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:
                return response.read()

        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            TimeoutError,
        ) as exc:
            last_error = exc

            if attempt < attempts:
                time.sleep(float(attempt))

    raise RealBenchmarkDataError(
        f"Download failed for {url}: {last_error}"
    )


def parse_epss_snapshot(
    payload: bytes,
) -> pd.DataFrame:
    try:
        decompressed = gzip.decompress(payload)
    except OSError as exc:
        raise RealBenchmarkDataError(
            "EPSS snapshot is not valid gzip data."
        ) from exc

    try:
        frame = pd.read_csv(
            io.BytesIO(decompressed),
            comment="#",
        )
    except Exception as exc:
        raise RealBenchmarkDataError(
            "EPSS CSV parsing failed."
        ) from exc

    expected = {
        "cve",
        "epss",
        "percentile",
    }

    if not expected.issubset(frame.columns):
        raise RealBenchmarkDataError(
            "EPSS CSV is missing required columns."
        )

    frame = frame[
        [
            "cve",
            "epss",
            "percentile",
        ]
    ].copy()

    frame["cve"] = (
        frame["cve"]
        .astype(str)
        .str.strip()
        .str.upper()
    )

    frame["epss"] = pd.to_numeric(
        frame["epss"],
        errors="coerce",
    )

    frame["percentile"] = pd.to_numeric(
        frame["percentile"],
        errors="coerce",
    )

    frame = frame.dropna(
        subset=[
            "cve",
            "epss",
            "percentile",
        ]
    )

    frame = frame[
        frame["cve"].str.match(
            r"^CVE-\d{4}-\d{4,}$"
        )
    ]

    frame = frame[
        frame["epss"].between(
            0.0,
            1.0,
        )
        & frame["percentile"].between(
            0.0,
            1.0,
        )
    ]

    frame = (
        frame.sort_values(
            [
                "cve",
                "epss",
            ],
            ascending=[
                True,
                False,
            ],
        )
        .drop_duplicates(
            subset=["cve"],
            keep="first",
        )
        .reset_index(drop=True)
    )

    if len(frame) < 100_000:
        raise RealBenchmarkDataError(
            "EPSS snapshot contains fewer than "
            "100,000 validated records."
        )

    return frame


def fetch_latest_epss(
    cache_dir: Path,
    *,
    days_back: int = 10,
    timeout: float = 60.0,
) -> tuple[
    pd.DataFrame,
    dict[str, Any],
]:
    today = datetime.now(
        timezone.utc
    ).date()

    errors: list[str] = []

    for offset in range(days_back + 1):
        candidate = today - timedelta(
            days=offset
        )

        date_text = candidate.isoformat()

        url = EPSS_URL_TEMPLATE.format(
            score_date=date_text
        )

        try:
            payload = download_bytes(
                url,
                timeout=timeout,
            )

            frame = parse_epss_snapshot(
                payload
            )

        except RealBenchmarkDataError as exc:
            errors.append(
                f"{date_text}: {exc}"
            )
            continue

        cache_path = (
            cache_dir
            / f"epss_scores-{date_text}.csv.gz"
        )

        cache_path.write_bytes(payload)

        return frame, {
            "score_date": date_text,
            "url": url,
            "cache_path": str(cache_path),
            "sha256": sha256_bytes(payload),
            "rows": int(len(frame)),
        }

    raise RealBenchmarkDataError(
        "No valid recent EPSS snapshot was "
        "available. Attempts: "
        + " | ".join(errors)
    )


def parse_kev_catalog(
    payload: bytes,
) -> tuple[
    set[str],
    dict[str, Any],
]:
    try:
        document = json.loads(
            payload.decode("utf-8")
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise RealBenchmarkDataError(
            "CISA KEV catalog is not valid JSON."
        ) from exc

    if not isinstance(document, Mapping):
        raise RealBenchmarkDataError(
            "CISA KEV root must be an object."
        )

    vulnerabilities = document.get(
        "vulnerabilities"
    )

    if not isinstance(
        vulnerabilities,
        list,
    ):
        raise RealBenchmarkDataError(
            "CISA KEV vulnerabilities are missing."
        )

    cves = {
        str(record.get("cveID"))
        .strip()
        .upper()
        for record in vulnerabilities
        if isinstance(record, Mapping)
        and str(record.get("cveID", ""))
        .strip()
        .upper()
        .startswith("CVE-")
    }

    if len(cves) < 500:
        raise RealBenchmarkDataError(
            "CISA KEV catalog contains fewer than "
            "500 validated CVEs."
        )

    metadata = {
        "catalog_version": document.get(
            "catalogVersion"
        ),
        "date_released": document.get(
            "dateReleased"
        ),
        "declared_count": document.get(
            "count"
        ),
        "validated_cves": len(cves),
    }

    return cves, metadata


def fetch_kev(
    cache_dir: Path,
    *,
    timeout: float = 60.0,
) -> tuple[
    set[str],
    dict[str, Any],
]:
    payload = download_bytes(
        CISA_KEV_URL,
        timeout=timeout,
    )

    cves, metadata = parse_kev_catalog(
        payload
    )

    cache_path = (
        cache_dir
        / "cisa_known_exploited_vulnerabilities.json"
    )

    cache_path.write_bytes(payload)

    return cves, {
        **metadata,
        "url": CISA_KEV_URL,
        "cache_path": str(cache_path),
        "sha256": sha256_bytes(payload),
    }


def engineer_features(
    frame: pd.DataFrame,
    *,
    snapshot_date: str,
) -> pd.DataFrame:
    result = frame.copy()

    result["cve_year"] = pd.to_numeric(
        result["cve"].str.extract(
            r"^CVE-(\d{4})-",
            expand=False,
        ),
        errors="coerce",
    )

    score_year = date.fromisoformat(
        snapshot_date
    ).year

    result["cve_age_years"] = (
        score_year
        - result["cve_year"]
    ).clip(
        lower=0,
        upper=40,
    )

    clipped_epss = result["epss"].clip(
        1e-6,
        1.0 - 1e-6,
    )

    result["epss_log10"] = np.log10(
        clipped_epss
    )

    result["epss_logit"] = np.log(
        clipped_epss
        / (1.0 - clipped_epss)
    )

    result["percentile_squared"] = (
        result["percentile"] ** 2
    )

    result["epss_ge_0_10"] = (
        result["epss"] >= 0.10
    ).astype(int)

    result["epss_ge_0_50"] = (
        result["epss"] >= 0.50
    ).astype(int)

    result["percentile_ge_0_90"] = (
        result["percentile"] >= 0.90
    ).astype(int)

    result["percentile_ge_0_99"] = (
        result["percentile"] >= 0.99
    ).astype(int)

    result = result.dropna(
        subset=[
            "cve_year",
            "cve_age_years",
        ]
    )

    result["cve_year"] = (
        result["cve_year"]
        .astype(int)
    )

    result["cve_age_years"] = (
        result["cve_age_years"]
        .astype(int)
    )

    return result.reset_index(
        drop=True
    )


def build_real_benchmark_dataset(
    *,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    timeout: float = 60.0,
) -> dict[str, Any]:
    cache_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    epss_frame, epss_metadata = (
        fetch_latest_epss(
            cache_dir,
            timeout=timeout,
        )
    )

    kev_cves, kev_metadata = fetch_kev(
        cache_dir,
        timeout=timeout,
    )

    dataset = engineer_features(
        epss_frame,
        snapshot_date=epss_metadata[
            "score_date"
        ],
    )

    dataset["is_kev"] = (
        dataset["cve"].isin(kev_cves)
    ).astype(int)

    positives = int(
        dataset["is_kev"].sum()
    )

    if positives < 500:
        raise RealBenchmarkDataError(
            "Fewer than 500 KEV-positive CVEs "
            "were joined to EPSS."
        )

    if dataset["cve"].duplicated().any():
        raise RealBenchmarkDataError(
            "Benchmark contains duplicate CVEs."
        )

    dataset_path = (
        output_dir
        / "real_epss_kev_benchmark.csv.gz"
    )

    dataset.to_csv(
        dataset_path,
        index=False,
        compression={
            "method": "gzip",
            "mtime": 0,
        },
    )

    joined_kev = set(
        dataset.loc[
            dataset["is_kev"] == 1,
            "cve",
        ]
    )

    manifest = {
        "schema_version": "1.0.0",
        "dataset_id": (
            "AEG-REAL-KEV-"
            + hashlib.sha256(
                (
                    epss_metadata["sha256"]
                    + kev_metadata["sha256"]
                ).encode("utf-8")
            ).hexdigest()[:24].upper()
        ),
        "generated_at": utc_now(),
        "label_definition": (
            "CURRENT_CISA_KEV_MEMBERSHIP"
        ),
        "rows": int(len(dataset)),
        "positive_rows": positives,
        "negative_rows": int(
            len(dataset) - positives
        ),
        "positive_prevalence": float(
            dataset["is_kev"].mean()
        ),
        "unique_cves": int(
            dataset["cve"].nunique()
        ),
        "epss_source": epss_metadata,
        "kev_source": kev_metadata,
        "kev_cves_not_in_epss": sorted(
            kev_cves - joined_kev
        ),
        "dataset_path": str(
            dataset_path
        ),
        "dataset_sha256": sha256_file(
            dataset_path
        ),
        "governance": {
            "real_public_data": True,
            "personal_data": False,
            "customer_data": False,
            "future_exploitation_claim": False,
            "causal_claim": False,
            "authoritative_policy_engine": "SSVC",
            "model_authority": "ADVISORY_ONLY",
            "automated_disposition_permitted": False,
            "production_readiness": "BLOCKED",
        },
    }

    manifest_path = (
        output_dir
        / "real_epss_kev_benchmark_manifest.json"
    )

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    write_sidecar(dataset_path)
    write_sidecar(manifest_path)

    return manifest
