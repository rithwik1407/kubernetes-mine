#!/usr/bin/env bash
cd "$(dirname "$0")/.."
VENV="${IDS_VENV:-$HOME/.venv-ids}"
. "$VENV/bin/activate"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
python scripts/check_api.py || echo "Some checks failed - see FAIL lines above (dashboard still starting)"
cd dashboard && exec uvicorn app:app --host 127.0.0.1 --port 8000
