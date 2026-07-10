# Risk Management Plan

AegisSec-FedOps follows a risk-aware design inspired by government-grade vulnerability management and responsible AI principles.

## Main Risks and Controls

| Risk | Description | Control |
|---|---|---|
| Input tampering | SBOM or dependency evidence may be incomplete or manipulated | Validation & Trust Layer |
| False positive | CVE incorrectly mapped to component | Affectedness engine, source cross-checking |
| False negative | Real vulnerability missed | Multiple intelligence sources |
| Stale data | Cached vulnerability data outdated | Freshness checks and source timestamps |
| Unsafe output | Agent gives exploit instructions | Defensive-only guardrails |
| Over-automation | System acts without human oversight | Human review gate |
| Sector bias | One sector always over-prioritized | Fairness evaluation by sector |
| Audit gap | Decision cannot be explained later | Evidence ledger and audit logs |

## Human Review Triggers

- Low input trust
- Unknown affectedness
- Critical or Emergency priority
- SSVC and ML conflict
- Critical asset or sensitive sector
- Missing CVSS/EPSS/KEV evidence
