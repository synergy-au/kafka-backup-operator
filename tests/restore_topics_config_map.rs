use kafka_backup_operator::crd::KafkaRestoreSpec;
use serde_json::{json, Value};

fn restore_spec(topics_config_map: Value) -> KafkaRestoreSpec {
    serde_json::from_value(json!({
        "backupRef": {"name": "backup"},
        "kafkaCluster": {"bootstrapServers": ["kafka:9092"]},
        "topicsConfigMap": topics_config_map
    }))
    .expect("restore spec deserialises")
}

#[test]
fn topics_config_map_keys_default_when_omitted() {
    let spec = restore_spec(json!({"name": "restore-topics"}));
    let config_map = spec
        .topics_config_map
        .expect("ConfigMap reference is present");

    assert_eq!(config_map.name, "restore-topics");
    assert_eq!(config_map.topics_key, "topics");
    assert_eq!(config_map.topic_mappings_key, "topic_mappings");
}

#[test]
fn topics_config_map_custom_keys_round_trip_with_camel_case() {
    let spec = restore_spec(json!({
        "name": "restore-topics",
        "topicsKey": "included-topics",
        "topicMappingKey": "topic-mappings"
    }));

    let config_map = spec
        .topics_config_map
        .as_ref()
        .expect("ConfigMap reference is present");
    assert_eq!(config_map.topics_key, "included-topics");
    assert_eq!(config_map.topic_mappings_key, "topic-mappings");

    let serialized = serde_json::to_value(spec).expect("restore spec serialises");
    assert_eq!(
        serialized["topicsConfigMap"],
        json!({
            "name": "restore-topics",
            "topicsKey": "included-topics",
            "topicMappingKey": "topic-mappings"
        })
    );
}
