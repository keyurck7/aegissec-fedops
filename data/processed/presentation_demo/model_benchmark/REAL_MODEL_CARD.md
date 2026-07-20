# AegisSec-FedOps Real-Data Benchmark

## Purpose

Classify current CISA KEV membership using public
EPSS-derived features for an academic development
benchmark.

## Selected model

- Candidate: `logistic_c_10`
- Family: `logistic_regression`
- Threshold: `0.844979`
- Development gate: `PASS`

## Natural-prevalence test metrics

- Accuracy: `0.972489`
- Balanced accuracy: `0.866686`
- Precision: `0.119389`
- Recall: `0.759878`
- F1: `0.206356`
- ROC-AUC: `0.966710`
- PR-AUC: `0.382801`
- Brier score: `0.063665`
- ECE: `0.133978`

## Governance

This is not a future-exploitation prediction model.
It does not override SSVC, affectedness, human review,
or remediation authority. Production readiness remains
blocked.
