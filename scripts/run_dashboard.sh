#!/usr/bin/env bash
# Start the dashboard backend (serves the UI too). Open http://localhost:${PORT:-8000}
cd "$(dirname "$0")/.."
VENV="${IDS_VENV:-$HOME/.venv-ids}"
. "$VENV/bin/activate"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
python scripts/check_api.py || echo "Some checks failed - see FAIL lines above (dashboard still starting)"
cd dashboard && exec uvicorn app:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
