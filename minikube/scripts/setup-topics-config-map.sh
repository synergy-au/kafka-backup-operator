#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"$SCRIPT_DIR/setup.sh" topics-config-map

echo ""
echo "Waiting for both selected topics to contain messages..."
topics_have_messages=false
for attempt in $(seq 1 60); do
    has_messages=true
    for topic in backup-test-topic orders; do
        if ! kubectl exec kafka-0 -n confluent -- \
            kafka-run-class kafka.tools.GetOffsetShell \
            --broker-list kafka:9071 \
            --topic "$topic" 2>/dev/null |
            awk -F: '$3 ~ /^[0-9]+$/ && $3 > 0 { found = 1 } END { exit !found }'; then
            has_messages=false
            break
        fi
    done
    if [[ "$has_messages" == true ]]; then
        topics_have_messages=true
        break
    fi
    echo "  Waiting for both topics to receive messages... ($attempt/60)"
    sleep 5
done

if [[ "$topics_have_messages" != true ]]; then
    echo "The selected and excluded topics must both contain messages before the test." >&2
    exit 1
fi

echo "Starting the ConfigMap-backed backup..."
kubectl patch kafkabackup backup-test-topic -n confluent \
    --type merge \
    -p '{"spec":{"suspend":false}}'
