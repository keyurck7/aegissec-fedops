"""Governed multi-format evidence intake for AegisSec-FedOps."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote


PARSER_VERSION = "1.0.0"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_COMPONENTS = 10_000
MAX_VULNERABILITY_HINTS = 25_000

SUPPORTED_FORMATS = {
    "CYCLONEDX_JSON",
    "SPDX_JSON",
    "REQUIREMENTS_TXT",
    "PACKAGE_JSON",
    "PACKAGE_LOCK_JSON",
    "COMPONENT_CSV",
    "SYFT_JSON",
    "TRIVY_JSON",
}

EXECUTABLE_MAGIC = (
    b"MZ",
    b"\x7fELF",
    b"\xca\xfe\xba\xbe",
)

ARCHIVE_MAGIC = (
    b"PK\x03\x04",
    b"\x1f\x8b",
    b"7z\xbc\xaf\x27\x1c",
)

EXACT_VERSION_PATTERN = re.compile(
    r"^[vV]?\d+(?:\.\d+){0,5}"
    r"(?:[-+._][A-Za-z0-9._-]+)?$"
)

REQUIREMENT_PATTERN = re.compile(
    r"^\s*"
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]+\])?"
    r"\s*(?P<specifier>.*)$"
)

PURL_PATTERN = re.compile(
    r"^pkg:(?P<type>[^/]+)/(?P<body>[^?#]+)"
    r"(?:@(?P<version>[^?#]+))?"
)

ECOSYSTEM_MAP = {
    "python": "PyPI",
    "pypi": "PyPI",
    "npm": "npm",
    "node": "npm",
    "java": "Maven",
    "maven": "Maven",
    "golang": "Go",
    "go-module": "Go",
    "go": "Go",
    "rust": "crates.io",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "deb": "Debian",
    "rpm": "RPM",
    "apk": "Alpine",
}


class InputGatewayError(RuntimeError):
    """Fail-closed intake rejection with a stable reason code."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        filename: str,
        content_sha256: str,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.filename = filename
        self.content_sha256 = content_sha256


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_json_bytes(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
        + "\n"
    ).encode("utf-8")


def normalized_text(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip()

    return text or None


def normalized_ecosystem(value: Any) -> str | None:
    text = normalized_text(value)

    if text is None:
        return None

    return ECOSYSTEM_MAP.get(
        text.lower(),
        text,
    )


def exact_version(value: Any) -> str | None:
    text = normalized_text(value)

    if text is None:
        return None

    if EXACT_VERSION_PATTERN.fullmatch(text):
        return text.lstrip("vV")

    return None


def purl_fields(
    purl: str | None,
) -> tuple[str | None, str | None, str | None]:
    if not purl:
        return None, None, None

    match = PURL_PATTERN.match(
        purl.strip()
    )

    if not match:
        return None, None, None

    ecosystem = normalized_ecosystem(
        match.group("type")
    )

    body = unquote(
        match.group("body")
    )

    name = body.split("/")[-1]
    version = normalized_text(
        match.group("version")
    )

    return ecosystem, name, version


def component_record(
    *,
    name: Any,
    version: Any = None,
    raw_version: Any = None,
    ecosystem: Any = None,
    purl: Any = None,
    supplier: Any = None,
    scope: Any = None,
    source_location: Any = None,
) -> dict[str, Any]:
    normalized_purl = normalized_text(purl)

    purl_ecosystem, purl_name, purl_version = purl_fields(
        normalized_purl
    )

    normalized_name = (
        normalized_text(name)
        or purl_name
    )

    if normalized_name is None:
        raise ValueError(
            "Component name is missing."
        )

    normalized_ecosystem_value = (
        normalized_ecosystem(ecosystem)
        or purl_ecosystem
    )

    normalized_version = (
        exact_version(version)
        or exact_version(purl_version)
    )

    normalized_raw_version = (
        normalized_text(raw_version)
        or normalized_text(version)
        or normalized_text(purl_version)
    )

    if normalized_ecosystem_value is None:
        identity_status = "UNKNOWN_ECOSYSTEM"
    elif normalized_version is None:
        identity_status = "UNKNOWN_VERSION"
    elif normalized_purl:
        identity_status = "EXACT"
    else:
        identity_status = "PARTIAL"

    identity_document = {
        "name": normalized_name,
        "version": normalized_version,
        "raw_version": normalized_raw_version,
        "ecosystem": normalized_ecosystem_value,
        "purl": normalized_purl,
        "supplier": normalized_text(supplier),
        "scope": normalized_text(scope),
        "source_location": normalized_text(
            source_location
        ),
    }

    identity_bytes = canonical_json_bytes(
        identity_document
    )

    component_sha256 = sha256_bytes(
        identity_bytes
    )

    return {
        "component_id": (
            "AEG-CMP-"
            + component_sha256[:20].upper()
        ),
        **identity_document,
        "identity_status": identity_status,
        "component_sha256": component_sha256,
    }


def decode_text(
    payload: bytes,
    *,
    filename: str,
    content_sha256: str,
) -> str:
    try:
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputGatewayError(
            "Input is not valid UTF-8 text.",
            reason_code="INPUT_INVALID_UTF8",
            filename=filename,
            content_sha256=content_sha256,
        ) from exc


def parse_json_document(
    payload: bytes,
    *,
    filename: str,
    content_sha256: str,
) -> Any:
    text = decode_text(
        payload,
        filename=filename,
        content_sha256=content_sha256,
    )

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputGatewayError(
            f"Malformed JSON at line {exc.lineno}, "
            f"column {exc.colno}.",
            reason_code="INPUT_MALFORMED_JSON",
            filename=filename,
            content_sha256=content_sha256,
        ) from exc


def detect_format(
    payload: bytes,
    *,
    filename: str,
    content_sha256: str,
) -> tuple[str, Any | None]:
    lower_name = Path(filename).name.lower()
    stripped = payload.lstrip()

    if (
        lower_name.endswith(".json")
        or stripped.startswith(b"{")
        or stripped.startswith(b"[")
    ):
        document = parse_json_document(
            payload,
            filename=filename,
            content_sha256=content_sha256,
        )

        if not isinstance(document, dict):
            raise InputGatewayError(
                "Top-level JSON value must be an object.",
                reason_code="INPUT_JSON_ROOT_NOT_OBJECT",
                filename=filename,
                content_sha256=content_sha256,
            )

        if (
            str(document.get("bomFormat", "")).lower()
            == "cyclonedx"
        ):
            return "CYCLONEDX_JSON", document

        if str(
            document.get("spdxVersion", "")
        ).startswith("SPDX-"):
            return "SPDX_JSON", document

        if (
            "lockfileVersion" in document
            and (
                "packages" in document
                or "dependencies" in document
            )
        ):
            return "PACKAGE_LOCK_JSON", document

        if isinstance(
            document.get("artifacts"),
            list,
        ):
            return "SYFT_JSON", document

        if isinstance(
            document.get("Results"),
            list,
        ):
            return "TRIVY_JSON", document

        if any(
            key in document
            for key in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            )
        ):
            return "PACKAGE_JSON", document

        raise InputGatewayError(
            "JSON structure is not a supported evidence format.",
            reason_code="INPUT_UNSUPPORTED_JSON_STRUCTURE",
            filename=filename,
            content_sha256=content_sha256,
        )

    if lower_name == "requirements.txt":
        return "REQUIREMENTS_TXT", None

    if lower_name.endswith(".csv"):
        return "COMPONENT_CSV", None

    raise InputGatewayError(
        "Input format is not supported.",
        reason_code="INPUT_UNSUPPORTED_FORMAT",
        filename=filename,
        content_sha256=content_sha256,
    )


def parse_cyclonedx(
    document: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
    list[str],
]:
    components: list[dict[str, Any]] = []
    hints: list[dict[str, Any]] = []
    warnings: list[str] = []
    reasons = ["FORMAT_CYCLONEDX_DETECTED"]

    candidate_components: list[dict[str, Any]] = []

    metadata = document.get("metadata")

    if isinstance(metadata, dict):
        root_component = metadata.get("component")

        if isinstance(root_component, dict):
            candidate_components.append(
                root_component
            )

    raw_components = document.get("components", [])

    if not isinstance(raw_components, list):
        raise ValueError(
            "CycloneDX components must be an array."
        )

    candidate_components.extend(
        item
        for item in raw_components
        if isinstance(item, dict)
    )

    for index, item in enumerate(
        candidate_components
    ):
        components.append(
            component_record(
                name=item.get("name"),
                version=item.get("version"),
                raw_version=item.get("version"),
                ecosystem=(
                    item.get("type")
                    if item.get("type")
                    not in {
                        "library",
                        "application",
                        "framework",
                        "container",
                    }
                    else None
                ),
                purl=item.get("purl"),
                supplier=(
                    item.get("supplier", {}).get("name")
                    if isinstance(
                        item.get("supplier"),
                        dict,
                    )
                    else item.get("supplier")
                ),
                scope=item.get("scope"),
                source_location=(
                    f"components[{index}]"
                ),
            )
        )

    raw_vulnerabilities = document.get(
        "vulnerabilities",
        [],
    )

    if isinstance(raw_vulnerabilities, list):
        for vulnerability in raw_vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue

            vulnerability_id = normalized_text(
                vulnerability.get("id")
            )

            if vulnerability_id is None:
                continue

            affects = vulnerability.get(
                "affects",
                [],
            )

            if not isinstance(affects, list):
                affects = []

            if affects:
                for affected in affects:
                    reference = (
                        affected.get("ref")
                        if isinstance(affected, dict)
                        else None
                    )

                    hints.append(
                        {
                            "vulnerability_id": (
                                vulnerability_id
                            ),
                            "component_name": (
                                normalized_text(reference)
                            ),
                            "installed_version": None,
                            "source": "CYCLONEDX",
                            "authority": "ADVISORY_ONLY",
                        }
                    )
            else:
                hints.append(
                    {
                        "vulnerability_id": (
                            vulnerability_id
                        ),
                        "component_name": None,
                        "installed_version": None,
                        "source": "CYCLONEDX",
                        "authority": "ADVISORY_ONLY",
                    }
                )

    if not components:
        warnings.append(
            "CycloneDX document contains no components."
        )
        reasons.append(
            "NO_COMPONENTS_EXTRACTED"
        )

    return components, hints, warnings, reasons


def parse_spdx(
    document: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
    list[str],
]:
    components: list[dict[str, Any]] = []
    warnings: list[str] = []
    reasons = ["FORMAT_SPDX_DETECTED"]

    packages = document.get("packages", [])

    if not isinstance(packages, list):
        raise ValueError(
            "SPDX packages must be an array."
        )

    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            continue

        purl = None

        external_references = package.get(
            "externalRefs",
            [],
        )

        if isinstance(external_references, list):
            for reference in external_references:
                if not isinstance(reference, dict):
                    continue

                reference_type = str(
                    reference.get(
                        "referenceType",
                        ""
                    )
                ).lower()

                if reference_type == "purl":
                    purl = reference.get(
                        "referenceLocator"
                    )
                    break

        supplier = normalized_text(
            package.get("supplier")
        )

        if supplier and supplier.startswith(
            "Organization:"
        ):
            supplier = supplier.split(
                ":",
                1,
            )[1].strip()

        components.append(
            component_record(
                name=package.get("name"),
                version=package.get(
                    "versionInfo"
                ),
                raw_version=package.get(
                    "versionInfo"
                ),
                ecosystem=None,
                purl=purl,
                supplier=supplier,
                scope=None,
                source_location=(
                    f"packages[{index}]"
                ),
            )
        )

    if not components:
        warnings.append(
            "SPDX document contains no packages."
        )
        reasons.append(
            "NO_COMPONENTS_EXTRACTED"
        )

    return components, [], warnings, reasons


def parse_requirements(
    payload: bytes,
    *,
    filename: str,
    content_sha256: str,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
    list[str],
]:
    text = decode_text(
        payload,
        filename=filename,
        content_sha256=content_sha256,
    )

    components: list[dict[str, Any]] = []
    warnings: list[str] = []
    reasons = ["FORMAT_REQUIREMENTS_DETECTED"]

    for line_number, raw_line in enumerate(
        text.splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith(
            (
                "-r ",
                "--requirement ",
                "-e ",
                "--editable ",
                "git+",
                "http://",
                "https://",
            )
        ):
            warnings.append(
                f"Line {line_number} was not resolved locally: "
                f"{line[:100]}"
            )
            reasons.append(
                "EXTERNAL_REQUIREMENT_NOT_RESOLVED"
            )
            continue

        requirement_text = line.split(
            ";",
            1,
        )[0].strip()

        match = REQUIREMENT_PATTERN.match(
            requirement_text
        )

        if not match:
            warnings.append(
                f"Line {line_number} could not be parsed."
            )
            reasons.append(
                "REQUIREMENT_LINE_UNPARSED"
            )
            continue

        name = match.group("name")
        specifier = (
            match.group("specifier")
            or ""
        ).strip()

        version = None

        for prefix in ("===", "=="):
            if specifier.startswith(prefix):
                candidate = specifier[
                    len(prefix):
                ].split(",", 1)[0].strip()

                version = exact_version(
                    candidate
                )
                break

        components.append(
            component_record(
                name=name,
                version=version,
                raw_version=specifier or None,
                ecosystem="PyPI",
                purl=(
                    f"pkg:pypi/{name}@{version}"
                    if version
                    else None
                ),
                supplier=None,
                scope="runtime",
                source_location=(
                    f"line:{line_number}"
                ),
            )
        )

    return components, [], warnings, reasons


def parse_package_json(
    document: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
    list[str],
]:
    components: list[dict[str, Any]] = []
    warnings: list[str] = []
    reasons = ["FORMAT_PACKAGE_JSON_DETECTED"]

    dependency_groups = (
        ("dependencies", "runtime"),
        ("devDependencies", "development"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    )

    for group_name, scope in dependency_groups:
        group = document.get(
            group_name,
            {},
        )

        if not isinstance(group, dict):
            continue

        for name, version_spec in group.items():
            version = exact_version(
                version_spec
            )

            if version is None:
                warnings.append(
                    f"{group_name}:{name} uses a non-exact "
                    f"version specification: {version_spec}"
                )
                reasons.append(
                    "NON_EXACT_VERSION_SPECIFICATION"
                )

            components.append(
                component_record(
                    name=name,
                    version=version,
                    raw_version=version_spec,
                    ecosystem="npm",
                    purl=(
                        f"pkg:npm/{name}@{version}"
                        if version
                        else None
                    ),
                    supplier=None,
                    scope=scope,
                    source_location=(
                        f"{group_name}.{name}"
                    ),
                )
            )

    return components, [], warnings, reasons


def parse_package_lock(
    document: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
    list[str],
]:
    components: list[dict[str, Any]] = []
    warnings: list[str] = []
    reasons = ["FORMAT_PACKAGE_LOCK_DETECTED"]

    packages = document.get("packages")

    if isinstance(packages, dict):
        for location, package in packages.items():
            if not location:
                continue

            if not isinstance(package, dict):
                continue

            name = package.get("name")

            if not name:
                marker = "node_modules/"
                name = (
                    location.rsplit(
                        marker,
                        1,
                    )[-1]
                    if marker in location
                    else Path(location).name
                )

            version = exact_version(
                package.get("version")
            )

            components.append(
                component_record(
                    name=name,
                    version=version,
                    raw_version=package.get(
                        "version"
                    ),
                    ecosystem="npm",
                    purl=(
                        f"pkg:npm/{name}@{version}"
                        if version
                        else None
                    ),
                    supplier=None,
                    scope=(
                        "development"
                        if package.get("dev")
                        else "runtime"
                    ),
                    source_location=location,
                )
            )

        return components, [], warnings, reasons

    dependencies = document.get(
        "dependencies",
        {},
    )

    if isinstance(dependencies, dict):
        for name, package in dependencies.items():
            if not isinstance(package, dict):
                continue

            version = exact_version(
                package.get("version")
            )

            components.append(
                component_record(
                    name=name,
                    version=version,
                    raw_version=package.get(
                        "version"
                    ),
                    ecosystem="npm",
                    purl=(
                        f"pkg:npm/{name}@{version}"
                        if version
                        else None
                    ),
                    supplier=None,
                    scope=(
                        "development"
                        if package.get("dev")
                        else "runtime"
                    ),
                    source_location=(
                        f"dependencies.{name}"
                    ),
                )
            )

    return components, [], warnings, reasons


def parse_component_csv(
    payload: bytes,
    *,
    filename: str,
    content_sha256: str,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
    list[str],
]:
    text = decode_text(
        payload,
        filename=filename,
        content_sha256=content_sha256,
    )

    reader = csv.DictReader(
        io.StringIO(text)
    )

    if not reader.fieldnames:
        raise ValueError(
            "CSV header is missing."
        )

    lookup = {
        name.strip().lower(): name
        for name in reader.fieldnames
    }

    def column(
        *names: str,
    ) -> str | None:
        for name in names:
            if name.lower() in lookup:
                return lookup[name.lower()]

        return None

    name_column = column(
        "name",
        "package",
        "component",
        "component_name",
        "package_name",
    )

    if name_column is None:
        raise ValueError(
            "CSV requires a name or package column."
        )

    version_column = column(
        "version",
        "installed_version",
        "package_version",
    )

    ecosystem_column = column(
        "ecosystem",
        "package_type",
        "type",
    )

    purl_column = column(
        "purl",
        "package_url",
    )

    supplier_column = column(
        "supplier",
        "vendor",
    )

    scope_column = column(
        "scope",
        "environment",
    )

    components: list[dict[str, Any]] = []
    warnings: list[str] = []
    reasons = ["FORMAT_COMPONENT_CSV_DETECTED"]

    for row_number, row in enumerate(
        reader,
        start=2,
    ):
        name = normalized_text(
            row.get(name_column)
        )

        if name is None:
            warnings.append(
                f"CSV row {row_number} has no component name."
            )
            reasons.append(
                "CSV_ROW_WITHOUT_COMPONENT_NAME"
            )
            continue

        version_value = (
            row.get(version_column)
            if version_column
            else None
        )

        components.append(
            component_record(
                name=name,
                version=version_value,
                raw_version=version_value,
                ecosystem=(
                    row.get(ecosystem_column)
                    if ecosystem_column
                    else None
                ),
                purl=(
                    row.get(purl_column)
                    if purl_column
                    else None
                ),
                supplier=(
                    row.get(supplier_column)
                    if supplier_column
                    else None
                ),
                scope=(
                    row.get(scope_column)
                    if scope_column
                    else None
                ),
                source_location=(
                    f"row:{row_number}"
                ),
            )
        )

    return components, [], warnings, reasons


def parse_syft(
    document: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
    list[str],
]:
    artifacts = document.get(
        "artifacts",
        [],
    )

    if not isinstance(artifacts, list):
        raise ValueError(
            "Syft artifacts must be an array."
        )

    components: list[dict[str, Any]] = []
    warnings: list[str] = []
    reasons = ["FORMAT_SYFT_DETECTED"]

    for index, artifact in enumerate(
        artifacts
    ):
        if not isinstance(artifact, dict):
            continue

        locations = artifact.get(
            "locations",
            [],
        )

        source_location = None

        if isinstance(locations, list) and locations:
            first_location = locations[0]

            if isinstance(first_location, dict):
                source_location = (
                    first_location.get("path")
                    or first_location.get(
                        "realPath"
                    )
                )

        components.append(
            component_record(
                name=artifact.get("name"),
                version=artifact.get("version"),
                raw_version=artifact.get(
                    "version"
                ),
                ecosystem=artifact.get("type"),
                purl=artifact.get("purl"),
                supplier=artifact.get(
                    "foundBy"
                ),
                scope=None,
                source_location=(
                    source_location
                    or f"artifacts[{index}]"
                ),
            )
        )

    return components, [], warnings, reasons


def parse_trivy(
    document: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
    list[str],
]:
    results = document.get("Results", [])

    if not isinstance(results, list):
        raise ValueError(
            "Trivy Results must be an array."
        )

    components: list[dict[str, Any]] = []
    hints: list[dict[str, Any]] = []
    warnings = [
        "Trivy vulnerability records are advisory hints, "
        "not authoritative affectedness decisions."
    ]
    reasons = [
        "FORMAT_TRIVY_DETECTED",
        "SCANNER_FINDINGS_ADVISORY_ONLY",
    ]

    for result_index, result in enumerate(
        results
    ):
        if not isinstance(result, dict):
            continue

        result_type = result.get("Type")
        vulnerabilities = result.get(
            "Vulnerabilities",
            [],
        )

        if not isinstance(vulnerabilities, list):
            continue

        for vulnerability_index, vulnerability in enumerate(
            vulnerabilities
        ):
            if not isinstance(vulnerability, dict):
                continue

            package_identifier = vulnerability.get(
                "PkgIdentifier"
            )

            purl = None

            if isinstance(
                package_identifier,
                dict,
            ):
                purl = package_identifier.get(
                    "PURL"
                )

            package_name = vulnerability.get(
                "PkgName"
            )

            installed_version = vulnerability.get(
                "InstalledVersion"
            )

            components.append(
                component_record(
                    name=package_name,
                    version=installed_version,
                    raw_version=installed_version,
                    ecosystem=result_type,
                    purl=purl,
                    supplier=None,
                    scope=None,
                    source_location=(
                        f"Results[{result_index}]."
                        f"Vulnerabilities[{vulnerability_index}]"
                    ),
                )
            )

            vulnerability_id = normalized_text(
                vulnerability.get(
                    "VulnerabilityID"
                )
            )

            if vulnerability_id:
                hints.append(
                    {
                        "vulnerability_id": (
                            vulnerability_id
                        ),
                        "component_name": (
                            normalized_text(
                                package_name
                            )
                        ),
                        "installed_version": (
                            normalized_text(
                                installed_version
                            )
                        ),
                        "fixed_version": (
                            normalized_text(
                                vulnerability.get(
                                    "FixedVersion"
                                )
                            )
                        ),
                        "severity": (
                            normalized_text(
                                vulnerability.get(
                                    "Severity"
                                )
                            )
                        ),
                        "source": "TRIVY",
                        "authority": "ADVISORY_ONLY",
                    }
                )

    return components, hints, warnings, reasons


JSON_ADAPTERS: dict[
    str,
    Callable[
        [dict[str, Any]],
        tuple[
            list[dict[str, Any]],
            list[dict[str, Any]],
            list[str],
            list[str],
        ],
    ],
] = {
    "CYCLONEDX_JSON": parse_cyclonedx,
    "SPDX_JSON": parse_spdx,
    "PACKAGE_JSON": parse_package_json,
    "PACKAGE_LOCK_JSON": parse_package_lock,
    "SYFT_JSON": parse_syft,
    "TRIVY_JSON": parse_trivy,
}


def deduplicate_components(
    components: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    observed: dict[str, dict[str, Any]] = {}
    duplicate_count = 0

    for component in components:
        component_hash = component[
            "component_sha256"
        ]

        if component_hash in observed:
            duplicate_count += 1
            continue

        observed[component_hash] = component

    deduplicated = sorted(
        observed.values(),
        key=lambda item: (
            str(item.get("ecosystem") or ""),
            item["name"].lower(),
            str(item.get("version") or ""),
            item["component_id"],
        ),
    )

    return deduplicated, duplicate_count


def ingest_bytes(
    payload: bytes,
    *,
    filename: str,
    authorized: bool = True,
    declared_media_type: str | None = None,
) -> dict[str, Any]:
    safe_filename = Path(
        filename or "uploaded_input"
    ).name

    content_sha256 = sha256_bytes(
        payload
    )

    def reject(
        message: str,
        reason_code: str,
    ) -> None:
        raise InputGatewayError(
            message,
            reason_code=reason_code,
            filename=safe_filename,
            content_sha256=content_sha256,
        )

    if not authorized:
        reject(
            "Input collection is not authorized.",
            "INPUT_AUTHORIZATION_REQUIRED",
        )

    if len(payload) == 0:
        reject(
            "Input is empty.",
            "INPUT_EMPTY",
        )

    if len(payload) > MAX_UPLOAD_BYTES:
        reject(
            "Input exceeds the maximum upload size.",
            "INPUT_TOO_LARGE",
        )

    if payload.startswith(
        EXECUTABLE_MAGIC
    ):
        reject(
            "Executable content is prohibited.",
            "INPUT_EXECUTABLE_PROHIBITED",
        )

    if payload.startswith(
        ARCHIVE_MAGIC
    ):
        reject(
            "Archive uploads are prohibited.",
            "INPUT_ARCHIVE_PROHIBITED",
        )

    detected_format, parsed_document = detect_format(
        payload,
        filename=safe_filename,
        content_sha256=content_sha256,
    )

    if detected_format not in SUPPORTED_FORMATS:
        reject(
            "Detected format is unsupported.",
            "INPUT_UNSUPPORTED_FORMAT",
        )

    try:
        if detected_format in JSON_ADAPTERS:
            assert isinstance(
                parsed_document,
                dict,
            )

            (
                raw_components,
                vulnerability_hints,
                warnings,
                reason_codes,
            ) = JSON_ADAPTERS[
                detected_format
            ](
                parsed_document
            )

        elif detected_format == "REQUIREMENTS_TXT":
            (
                raw_components,
                vulnerability_hints,
                warnings,
                reason_codes,
            ) = parse_requirements(
                payload,
                filename=safe_filename,
                content_sha256=content_sha256,
            )

        elif detected_format == "COMPONENT_CSV":
            (
                raw_components,
                vulnerability_hints,
                warnings,
                reason_codes,
            ) = parse_component_csv(
                payload,
                filename=safe_filename,
                content_sha256=content_sha256,
            )

        else:
            reject(
                "No adapter is registered for the input.",
                "INPUT_ADAPTER_NOT_REGISTERED",
            )

    except InputGatewayError:
        raise
    except Exception as exc:
        raise InputGatewayError(
            f"Input adapter failed: {exc}",
            reason_code="INPUT_ADAPTER_FAILURE",
            filename=safe_filename,
            content_sha256=content_sha256,
        ) from exc

    if len(raw_components) > MAX_COMPONENTS:
        reject(
            "Input exceeds the maximum component count.",
            "INPUT_COMPONENT_LIMIT_EXCEEDED",
        )

    if (
        len(vulnerability_hints)
        > MAX_VULNERABILITY_HINTS
    ):
        reject(
            "Input exceeds the vulnerability hint limit.",
            "INPUT_HINT_LIMIT_EXCEEDED",
        )

    components, duplicate_count = (
        deduplicate_components(
            raw_components
        )
    )

    if duplicate_count:
        warnings.append(
            f"{duplicate_count} duplicate component "
            "records were detected and collapsed."
        )
        reason_codes.append(
            "DUPLICATE_COMPONENTS_DETECTED"
        )

    exact_count = sum(
        1
        for component in components
        if component["identity_status"]
        == "EXACT"
    )

    unknown_version_count = sum(
        1
        for component in components
        if component["identity_status"]
        == "UNKNOWN_VERSION"
    )

    unknown_ecosystem_count = sum(
        1
        for component in components
        if component["identity_status"]
        == "UNKNOWN_ECOSYSTEM"
    )

    if unknown_version_count:
        warnings.append(
            f"{unknown_version_count} components have "
            "no exact installed version."
        )
        reason_codes.append(
            "UNKNOWN_COMPONENT_VERSIONS"
        )

    if unknown_ecosystem_count:
        warnings.append(
            f"{unknown_ecosystem_count} components have "
            "no resolved ecosystem."
        )
        reason_codes.append(
            "UNKNOWN_COMPONENT_ECOSYSTEMS"
        )

    if not components:
        warnings.append(
            "No usable components were extracted."
        )
        reason_codes.append(
            "NO_COMPONENTS_EXTRACTED"
        )

    reason_codes = sorted(
        set(reason_codes)
    )

    warnings = sorted(
        set(warnings)
    )

    total_components = len(components)

    identity_completeness = (
        exact_count / total_components
        if total_components
        else 0.0
    )

    human_review_required = bool(
        warnings
        or vulnerability_hints
        or unknown_version_count
        or unknown_ecosystem_count
    )

    trust_action = (
        "ACCEPT_WITH_WARNINGS"
        if human_review_required
        else "ACCEPT"
    )

    envelope_without_integrity = {
        "schema_version": "1.0.0",
        "input_id": (
            "AEG-INP-"
            + content_sha256[:24].upper()
        ),
        "created_at": (
            datetime.now(
                timezone.utc
            ).isoformat()
        ),
        "source": {
            "filename": safe_filename,
            "size_bytes": len(payload),
            "sha256": content_sha256,
            "authorized": True,
            "declared_media_type": (
                declared_media_type
            ),
        },
        "detection": {
            "format": detected_format,
            "media_type": (
                "application/json"
                if detected_format.endswith(
                    "_JSON"
                )
                else (
                    "text/csv"
                    if detected_format
                    == "COMPONENT_CSV"
                    else "text/plain"
                )
            ),
            "method": (
                "CONTENT_AND_FILENAME"
            ),
            "parser_version": (
                PARSER_VERSION
            ),
        },
        "validation": {
            "stage_gate": "PASS",
            "errors": [],
            "warnings": warnings,
            "reason_codes": reason_codes,
        },
        "components": components,
        "vulnerability_hints": sorted(
            vulnerability_hints,
            key=lambda item: (
                item["vulnerability_id"],
                str(
                    item.get(
                        "component_name"
                    )
                    or ""
                ),
            ),
        ),
        "statistics": {
            "component_count": (
                total_components
            ),
            "raw_component_count": (
                len(raw_components)
            ),
            "exact_identity_count": (
                exact_count
            ),
            "unknown_version_count": (
                unknown_version_count
            ),
            "unknown_ecosystem_count": (
                unknown_ecosystem_count
            ),
            "duplicate_component_count": (
                duplicate_count
            ),
            "vulnerability_hint_count": (
                len(vulnerability_hints)
            ),
        },
        "trust": {
            "action": trust_action,
            "parser_confidence": (
                "HIGH"
                if components
                else "LOW"
            ),
            "identity_completeness": (
                round(
                    identity_completeness,
                    6,
                )
            ),
            "human_review_required": (
                human_review_required
            ),
        },
        "governance": {
            "authority": (
                "INPUT_EVIDENCE_ONLY"
            ),
            "may_determine_affectedness_alone": (
                False
            ),
            "may_override_ssvc": False,
            "automated_disposition_permitted": (
                False
            ),
            "final_disposition_authority": (
                "HUMAN"
            ),
            "production_readiness": (
                "BLOCKED"
            ),
        },
    }

    envelope_sha256 = sha256_bytes(
        canonical_json_bytes(
            envelope_without_integrity
        )
    )

    return {
        **envelope_without_integrity,
        "integrity": {
            "content_sha256": (
                content_sha256
            ),
            "envelope_sha256": (
                envelope_sha256
            ),
        },
    }


def verify_envelope_integrity(
    envelope: dict[str, Any],
) -> bool:
    integrity = envelope.get(
        "integrity"
    )

    if not isinstance(integrity, dict):
        return False

    expected = integrity.get(
        "envelope_sha256"
    )

    if not isinstance(expected, str):
        return False

    unsigned = {
        key: value
        for key, value in envelope.items()
        if key != "integrity"
    }

    observed = sha256_bytes(
        canonical_json_bytes(unsigned)
    )

    return observed == expected


def serialize_envelope(
    envelope: dict[str, Any],
) -> bytes:
    if not verify_envelope_integrity(
        envelope
    ):
        raise ValueError(
            "Envelope integrity verification failed."
        )

    return canonical_json_bytes(
        envelope
    )
