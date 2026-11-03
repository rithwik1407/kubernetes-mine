#!/usr/bin/env bash
# Build config/ids-controller.kubeconfig from the ids-controller service-account
# token, so the backend talks to the API server with least privilege instead of
# the admin kubeconfig. Revoke by deleting secret ids-controller-token.
set -euo pipefail
cd "$(dirname "$0")/../.."
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
OUT=config/ids-controller.kubeconfig

for _ in $(seq 30); do
    TOKEN=$(kubectl -n ids-deception get secret ids-controller-token -o jsonpath='{.data.token}' 2>/dev/null | base64 -d || true)
    [ -n "$TOKEN" ] && break
    sleep 1
done
[ -n "$TOKEN" ] || { echo "token not populated"; exit 1; }
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA=$(kubectl -n ids-deception get secret ids-controller-token -o jsonpath='{.data.ca\.crt}')

umask 077
cat > "$OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: k3s
  cluster:
    server: $SERVER
    certificate-authority-data: $CA
users:
- name: ids-controller
  user:
    token: $TOKEN
contexts:
- name: ids-controller
  context: {cluster: k3s, user: ids-controller, namespace: ids-deception}
current-context: ids-controller
EOF
echo "wrote $OUT"
