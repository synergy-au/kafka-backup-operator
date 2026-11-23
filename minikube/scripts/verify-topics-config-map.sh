#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINIKUBE_DIR="$(dirname "$SCRIPT_DIR")"
NAMESPACE="confluent"
BACKUP_NAME="backup-test-topic"
RESTORE_NAME="restore-topics-config-map"
MANIFEST_POD="topics-config-map-manifest-checker"
TEMP_DIR="$(mktemp -d)"
MANIFEST_FILE="$TEMP_DIR/manifest.json"

cleanup() {
    kubectl delete pod "$MANIFEST_POD" -n "$NAMESPACE" --ignore-not-found=true >/dev/null 2>&1 || true
    rm -f "$MANIFEST_FILE"
    rmdir "$TEMP_DIR"
}
trap cleanup EXIT

echo "============================================"
echo "Topics ConfigMap E2E Verification"
echo "============================================"

echo ""
echo "1. Waiting for the ConfigMap-backed backup to complete..."
kubectl wait --for='jsonpath={.status.phase}=Completed' \
    "kafkabackup/$BACKUP_NAME" -n "$NAMESPACE" --timeout=10m

include_key="$(kubectl get kafkabackup "$BACKUP_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.spec.topicsConfigMap.topicsIncludeKey}')"
exclude_key="$(kubectl get kafkabackup "$BACKUP_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.spec.topicsConfigMap.topicsExcludeKey}')"
if [[ "$include_key" != backup_topics || "$exclude_key" != excluded_topics ]]; then
    echo "Unexpected backup ConfigMap keys: include=$include_key exclude=$exclude_key" >&2
    exit 1
fi

backup_id="$(kubectl get kafkabackup "$BACKUP_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.status.backupId}')"
if [[ -z "$backup_id" ]]; then
    echo "KafkaBackup has no status.backupId after completing." >&2
    exit 1
fi

echo ""
echo "2. Checking the backup manifest includes only the selected topic..."
kubectl run "$MANIFEST_POD" --image=busybox --restart=Never -n "$NAMESPACE" \
    --overrides='{"apiVersion":"v1","spec":{"containers":[{"name":"manifest-checker","image":"busybox","command":["sh","-c","sleep 3600"],"volumeMounts":[{"name":"backup-storage","mountPath":"/backup"}]}],"volumes":[{"name":"backup-storage","persistentVolumeClaim":{"claimName":"kafka-backup-storage"}}]}}'
kubectl wait --for=condition=Ready "pod/$MANIFEST_POD" -n "$NAMESPACE" --timeout=120s
kubectl cp -n "$NAMESPACE" \
    "$MANIFEST_POD:/backup/backups/$backup_id/manifest.json" "$MANIFEST_FILE"
python3 - "$MANIFEST_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as manifest_file:
    manifest = json.load(manifest_file)

topics = {topic["name"] for topic in manifest["topics"]}
expected = {"backup-test-topic"}
if topics != expected:
    raise SystemExit(f"Expected backup topics {sorted(expected)}, got {sorted(topics)}")

print(f"Backup manifest topics: {', '.join(sorted(topics))}")
PY
kubectl delete pod "$MANIFEST_POD" -n "$NAMESPACE" --wait=true

echo ""
echo "3. Applying the ConfigMap-backed restore..."
kubectl apply -f "$MINIKUBE_DIR/overlays/topics-config-map/kafka-restore.yaml"
kubectl wait --for='jsonpath={.status.phase}=Completed' \
    "kafkarestore/$RESTORE_NAME" -n "$NAMESPACE" --timeout=10m

restore_topics_key="$(kubectl get kafkarestore "$RESTORE_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.spec.topicsConfigMap.topicsKey}')"
restore_mappings_key="$(kubectl get kafkarestore "$RESTORE_NAME" -n "$NAMESPACE" \
    -o jsonpath='{.spec.topicsConfigMap.topicMappingsKey}')"
if [[ "$restore_topics_key" != restore_topics || "$restore_mappings_key" != topic_mappings ]]; then
    echo "Unexpected restore ConfigMap keys: topics=$restore_topics_key mappings=$restore_mappings_key" >&2
    exit 1
fi

restored_offsets="$(kubectl exec kafka-0 -n "$NAMESPACE" -- \
    kafka-run-class kafka.tools.GetOffsetShell \
    --broker-list kafka:9071 \
    --topic restored-topic |
    awk -F: '$3 ~ /^[0-9]+$/ { total += $3 } END { print total + 0 }')"
if [[ "$restored_offsets" -le 0 ]]; then
    echo "The ConfigMap topic mapping did not produce records in restored-topic." >&2
    exit 1
fi

echo "Restored topic contains $restored_offsets records."
echo ""
echo "Topics ConfigMap backup and restore checks passed."
