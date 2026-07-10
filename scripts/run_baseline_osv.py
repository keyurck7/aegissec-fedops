import json
import sys
from pathlib import Path

import pandas as pd

sys.path.append(str(Path(__file__).resolve().parents[1]))

from src.ingestion.requirements_parser import parse_requirements_file
from src.ingestion.package_json_parser import parse_package_json
from src.intelligence.osv_client import load_or_query_osv, flatten_osv_results


ASSET_ID = "ASSET-001"

components = []
components.extend(parse_requirements_file("data/sample_inputs/citizen_portal/requirements.txt", ASSET_ID))
components.extend(parse_package_json("data/sample_inputs/citizen_portal/package.json", ASSET_ID))

components_df = pd.DataFrame(components)
print("\\nParsed components:")
print(components_df)

all_findings = []

for component in components:
    print(f"Querying OSV: {component['ecosystem']} / {component['component_name']} / {component.get('version')}")
    try:
        osv_data = load_or_query_osv(component)
        all_findings.extend(flatten_osv_results(component, osv_data))
    except Exception as exc:
        print(f"OSV query failed for {component['component_name']}: {exc}")

findings_df = pd.DataFrame(all_findings)
print("\\nOSV findings:")
print(findings_df)

Path("data/processed").mkdir(parents=True, exist_ok=True)
components_df.to_csv("data/processed/components_baseline.csv", index=False)
findings_df.to_csv("data/processed/osv_findings_baseline.csv", index=False)

print("\\nSaved:")
print("data/processed/components_baseline.csv")
print("data/processed/osv_findings_baseline.csv")
