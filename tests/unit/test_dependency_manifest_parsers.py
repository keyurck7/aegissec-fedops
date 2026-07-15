from pathlib import Path

from src.ingestion.package_json_parser import parse_package_json
from src.ingestion.requirements_parser import parse_requirements_file


def test_requirements_parser_preserves_hashes_and_exact_pin(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text("requests==2.32.5 --hash=sha256:" + "a" * 64 + "\n")
    result = parse_requirements_file(str(path), "AST-1", strict_supply_chain=True)
    assert result[0]["is_exact_pin"] is True
    assert result[0]["hashes"]["sha256"] == ["a" * 64]
    assert result[0]["validation_issue"] is None


def test_requirements_parser_does_not_treat_range_as_version(tmp_path: Path) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text("requests>=2\n")
    result = parse_requirements_file(str(path), "AST-1", strict_supply_chain=True)
    assert result[0]["version"] is None
    assert result[0]["is_exact_pin"] is False


def test_package_json_parser_preserves_range_semantics(tmp_path: Path) -> None:
    path = tmp_path / "package.json"
    path.write_text('{"dependencies":{"axios":"^1.2.3","lodash":"4.17.21"}}')
    result = parse_package_json(str(path), "AST-1")
    by_name = {item["component_name"]: item for item in result}
    assert by_name["axios"]["version"] is None
    assert by_name["axios"]["specifier_type"] == "range"
    assert by_name["lodash"]["version"] == "4.17.21"
