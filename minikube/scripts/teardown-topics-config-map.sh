#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINIKUBE_DIR="$(dirname "$SCRIPT_DIR")"

kubectl delete -f "$MINIKUBE_DIR/overlays/topics-config-map/kafka-restore.yaml" \
    --ignore-not-found=true
"$SCRIPT_DIR/teardown.sh" topics-config-map
