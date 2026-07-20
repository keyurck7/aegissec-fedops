# Milestone 12F: Independent ML Advisory

This implementation creates a development-only, provenance-governed ML advisory that is structurally unable to replace the authoritative SSVC decision.

## Controls

- Strict model-feature allowlist inherited from the 12F.1B governance contract.
- Explicit leakage firewall for SSVC, outcome, disposition, review and release fields.
- Label provenance validation and identity matching.
- Controlled synthetic scenarios are marked development-only and never production eligible.
- Group-isolated deterministic train, validation and test split.
- Calibrated random-forest advisory with abstention.
- Out-of-distribution detection for numeric ranges and unseen categories.
- Held-out permutation importance for global XAI.
- Slice metrics across criticality, mission essentiality, health data and external exposure.
- Agreement preview where SSVC remains authoritative under every outcome.

## Required production work

Synthetic evidence cannot establish real-world validity. Production release remains blocked until an approved independent outcome dataset, temporal external validation, model risk approval, drift monitoring, security testing, privacy review and human governance sign-off exist.
