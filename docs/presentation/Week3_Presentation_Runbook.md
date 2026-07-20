# AegisSec-FedOps Week 3 Presentation Runbook

## Demonstration boundary

This is a controlled academic development demonstration.

- SSVC is authoritative.
- Machine learning is advisory-only.
- The model classifies current CISA KEV membership.
- It does not predict future exploitation.
- Automated remediation is prohibited.
- Production readiness remains blocked.

## Ten-minute sequence

### 0:00–0:45 — Opening

Software vulnerability teams do not suffer from a lack of CVEs.
They suffer from disconnected evidence, weak prioritization and
unclear decision authority.

AegisSec-FedOps connects component identity, live vulnerability
intelligence, exploitation evidence, operational context, policy
and responsible machine learning.

### 0:45–1:30 — Architecture

Show Pipeline Architecture.

Explain:

Inventory → validation → OSV affectedness → CISA KEV and EPSS →
sector context → SQLite evidence mart → SSVC and independent ML →
agreement, abstention and human review.

### 1:30–2:30 — Executive overview

Show:

- 16 controlled components
- 15 vulnerable components
- 2 components with known-exploited vulnerabilities
- Four sectors
- Operational attention queue

State that this is a controlled demonstration inventory, not customer data.

### 2:30–3:45 — Component explorer

Open AEG-CMP-0001, Log4j.

Explain:

- Exact package and version
- Healthcare context
- CISA KEV evidence
- EPSS evidence
- Mission and asset context
- Human-review requirement

### 3:45–4:30 — Threat intelligence

Show live OSV, CISA KEV and FIRST EPSS evidence.

Explain that:

- OSV establishes package/version vulnerability matches.
- KEV establishes confirmed exploitation in the wild.
- EPSS provides exploitation-likelihood evidence.
- None is a complete operational decision by itself.

### 4:30–6:15 — Real-data ML benchmark

Show:

- 349,491 real CVE records
- 1,647 KEV positives
- Seven candidate configurations
- Logistic Regression winner
- 86.67% balanced accuracy
- 75.99% recall
- 38.28% PR-AUC
- 96.67% ROC-AUC
- 11.94% precision

State:

Accuracy is not our primary metric because KEV prevalence is only
0.47%. The model is a high-recall triage assistant and produces
false positives that require review.

### 6:15–8:15 — XAI and error analysis

Show:

- Global directional coefficients
- Odds ratios
- True-positive example
- False-positive example
- False-negative example
- True-negative example
- Local additive contributions
- EPSS weakness slices
- Exact probability reconstruction error of approximately 1.11e-16

State:

The local explanations mathematically reproduce the model probability.
They are not decorative explanations.

### 8:15–9:15 — Testing and coverage

Show:

- 493 tests passed
- 92% XAI-focused coverage
- 80.45% full-source coverage
- Eight of eight automated XAI checks passed
- Integrity and fail-closed controls

### 9:15–10:00 — Governance conclusion

State:

The model cannot override affectedness, SSVC or human review.
False positives demonstrate review burden. False negatives demonstrate
why the model cannot replace CISA evidence or policy.

AegisSec-FedOps does not hide uncertainty. It operationalizes it.

## Closing line

We did not build a model that merely predicts a label. We built an
evidence-governed decision system that knows when data is strong, when
the model is uncertain and when authority must remain with policy and
human reviewers.
