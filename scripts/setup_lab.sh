#!/usr/bin/env bash
# One-time lab setup. Run inside WSL2 / Linux on the machine that runs K3s:
#     bash scripts/setup_lab.sh
# Then start the dashboard:  bash scripts/run_dashboard.sh   (http://localhost:8000)
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Python environment"
VENV="${IDS_VENV:-$HOME/.venv-ids}"
[ -f "$VENV/bin/activate" ] || python3 -m venv "$VENV"
. "$VENV/bin/activate"
pip install -q -r requirements.txt

echo "== tcpdump (capture without sudo)"
command -v tcpdump >/dev/null || sudo apt-get install -y tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(command -v tcpdump)")" || echo "setcap failed; capture will need sudo"

echo "== Kubernetes"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
if [ ! -f "$KUBECONFIG" ] && [ -r /etc/rancher/k3s/k3s.yaml ]; then
    mkdir -p "$(dirname "$KUBECONFIG")"; cp /etc/rancher/k3s/k3s.yaml "$KUBECONFIG"
fi
kubectl apply -f deploy/namespaces/
kubectl apply -k deploy/traffic-lab
kubectl apply -k deploy/deception
kubectl apply -f deploy/rbac/ids-controller.yaml
bash deploy/rbac/create-kubeconfig.sh

echo "== Target apps (namespace target-apps)"
kubectl -n target-apps get pods 2>/dev/null || echo "namespace target-apps not found: deploy Node-RED, Grafana and InfluxDB there"
echo "Done. Start the dashboard with: bash scripts/run_dashboard.sh"
