# AegisSec-FedOps

AegisSec-FedOps is a sector-aware vulnerability intelligence agent for critical digital services.

It analyzes software evidence such as SBOMs and dependency files, validates input trust, enriches vulnerabilities with official intelligence sources, and prioritizes remediation using a dual engine:

1. SSVC-style policy decision tree
2. ML priority classifier
3. Agreement checker and human review workflow

## Target Sectors

- Public Administration
- Healthcare
- Defence Logistics
- Germany/EU Public Sector Context

## Core Sources

- OSV.dev
- NVD
- FIRST EPSS
- CISA KEV
- GitHub Advisories
- deps.dev
- CISA Advisories
- NIST guidance
- HHS/FDA healthcare cybersecurity
- DoD STIGs
- NSA advisories
- BSI/CERT-Bund
- ENISA EUVD
- MITRE ATT&CK

## Professional Boundary

AegisSec uses official public intelligence and authorized software evidence. It does not perform unauthorized scanning, exploitation, or collection of sensitive real systems.
