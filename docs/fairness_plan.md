# Fairness Plan

AegisSec-FedOps evaluates fairness as consistency and justified treatment across sectors, asset types, and evidence quality.

## Fairness Groups

- Public Administration
- Healthcare
- Defence Logistics
- Germany/EU Public Sector
- Internet-facing assets
- Internal assets
- High-trust inputs
- Low-trust inputs

## Fairness Risks

| Fairness Risk | Example | Mitigation |
|---|---|---|
| Sector over-prioritization | Defence always becomes Critical | Compare priority distribution by sector |
| Sector under-prioritization | Healthcare internal systems marked low despite patient impact | Include patient-safety and continuity features |
| Exposure bias | Internal assets always treated as low priority | Add mission impact and data sensitivity |
| Missing-data bias | Missing EPSS treated as zero risk | Mark as Unknown, not Low |
| Trust-level bias | Low-trust evidence ignored instead of reviewed | Human-review queue |

## Metrics

- Priority distribution by sector
- Human review rate by sector
- Emergency/Critical rate by sector
- False positive review rate by sector
- Unknown affectedness rate by sector
- Missing-data rate by source
