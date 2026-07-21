#!/usr/bin/env bash

set -euo pipefail

cd "$HOME/vault/aegissec-fedops"

python scripts/build_aegissec_presentation_notebook.py
python scripts/run_command_center_smoke.py

echo
echo "Starting AegisSec-FedOps Streamlit command center"
echo "Local port: 8501"
echo "DataLab proxy path: /user/keyurck7/proxy/8501/"
echo "Stop with Ctrl+C"
echo

python -m streamlit run \
  app/aegissec_command_center.py \
  --server.address 0.0.0.0 \
  --server.port 8501 \
  --server.headless true
