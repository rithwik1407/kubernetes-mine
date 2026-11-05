#!/usr/bin/env bash
# One-time lab setup. Run inside WSL2 / Linux on the machine that runs K3s:
#     bash scripts/setup_lab.sh
# Then start the dashboard:  bash scripts/run_dashboard.sh   (http://localhost:8000)
#
# What it changes on this machine (all needed by the live pipeline):
#   * apt packages: tcpdump, libpcap-dev (CICFlowMeter's jnetpcap needs libpcap.so),
#     openjdk-17-jdk-headless + maven (to build CICFlowMeter once), git
#   * setcap on tcpdump so capture works without sudo
#   * ~/CICFlowMeter: the GintsEngelen CICFlowMeter fork, built with maven (skipped if present)
# Kubernetes: namespaces ids-traffic / ids-deception, the traffic lab, the decoy
# server ConfigMap + NetworkPolicies, the least-privilege ids-controller RBAC, and the
# target apps ONLY if target-apps has no Node-RED/Grafana/InfluxDB yet.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== System packages"
need=()
command -v tcpdump >/dev/null || need+=(tcpdump)
command -v java >/dev/null || need+=(openjdk-17-jdk-headless)
command -v mvn >/dev/null || need+=(maven)
command -v git >/dev/null || need+=(git)
ldconfig -p 2>/dev/null | grep -q 'libpcap.so ' || need+=(libpcap-dev)
if [ ${#need[@]} -gt 0 ]; then sudo apt-get update -q && sudo apt-get install -y -q "${need[@]}"; fi

echo "== Python environment"
VENV="${IDS_VENV:-$HOME/.venv-ids}"
[ -f "$VENV/bin/activate" ] || python3 -m venv "$VENV"
. "$VENV/bin/activate"
pip install -q -r requirements.txt

echo "== tcpdump (capture without sudo)"
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$(command -v tcpdump)")" || echo "setcap failed; capture will need sudo"

echo "== CICFlowMeter"
CFM="$HOME/CICFlowMeter"
if [ ! -f "$CFM/target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar" ]; then
    [ -d "$CFM" ] || git clone --depth 1 https://github.com/GintsEngelen/CICFlowMeter.git "$CFM"
    (cd "$CFM" && mvn -q install:install-file -Dfile=jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar \
        -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar \
     && mvn -q -DskipTests package)
fi
python -c "from live.cicflowmeter import support; s=support(); print('CICFlowMeter:', 'ready' if s['supported'] else s['reason'])"

echo "== Kubernetes"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
if [ ! -f "$KUBECONFIG" ] && [ -f /etc/rancher/k3s/k3s.yaml ]; then
    mkdir -p "$(dirname "$KUBECONFIG")"; sudo cp /etc/rancher/k3s/k3s.yaml "$KUBECONFIG"; sudo chown "$USER" "$KUBECONFIG"
fi
kubectl get nodes
if ! kubectl -n target-apps get deploy 2>/dev/null | grep -qE 'nodered|grafana|influxdb'; then
    echo "target-apps has no lab apps: deploying Node-RED, Grafana, InfluxDB (deploy/target-apps)"
    kubectl apply -f deploy/target-apps/
fi
kubectl apply -f deploy/namespaces/
kubectl apply -k deploy/traffic-lab
kubectl apply -k deploy/deception
kubectl apply -f deploy/rbac/ids-controller.yaml
bash deploy/rbac/create-kubeconfig.sh

echo "== Target apps (namespace target-apps)"
kubectl -n target-apps get pods
echo "Done. Start the dashboard with: bash scripts/run_dashboard.sh"
