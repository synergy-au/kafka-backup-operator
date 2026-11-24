use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

use http::{Request, Response};
use kafka_backup_operator::adapters::{build_topic_config, build_topic_restore_config};
use kafka_backup_operator::crd::{KafkaRestoreSpec, TopicConfigMap};
use kafka_backup_operator::error::Error;
use kube::{client::Body, Client};
use serde_json::{json, Value};
use tower_test::mock;

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
        "topicMappingsKey": "topic-mappings"
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
            "topicMappingsKey": "topic-mappings"
        })
    );
}

fn config_map_client(data: Value) -> (Client, tokio::task::JoinHandle<()>) {
    let (service, mut handle) = mock::pair::<Request<Body>, Response<Body>>();
    let client = Client::new(service, "backups");
    let server = tokio::spawn(async move {
        let (request, send) = handle.next_request().await.unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(
            request.uri().path(),
            "/api/v1/namespaces/selection/configmaps/topic-selection"
        );
        send.send_response(
            Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "apiVersion": "v1",
                        "kind": "ConfigMap",
                        "metadata": {"name": "topic-selection", "namespace": "selection"},
                        "data": data
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        );
    });
    (client, server)
}

fn backup_config_map() -> Option<TopicConfigMap> {
    Some(
        serde_json::from_value(json!({
            "name": "topic-selection",
            "namespace": "selection",
            "topicsIncludeKey": "included",
            "topicsExcludeKey": "excluded"
        }))
        .unwrap(),
    )
}

fn restore_config_map() -> KafkaRestoreSpec {
    restore_spec(json!({
        "name": "topic-selection",
        "namespace": "selection",
        "topicsKey": "included",
        "topicMappingsKey": "mappings"
    }))
}

#[tokio::test]
async fn backup_include_and_exclude_accept_all_list_formats() {
    for (included, excluded) in [
        (" orders, , events, ", " events, "),
        ("orders\r\n\r\nevents\r\n", " events\n"),
        ("- orders\n- ''\n- events\n", "- events\n"),
        ("[orders, events]", "[events]"),
    ] {
        let (client, server) =
            config_map_client(json!({"included": included, "excluded": excluded}));
        let resolved =
            build_topic_config(&vec![], &vec![], &backup_config_map(), &client, "backups")
                .await
                .unwrap();
        server.await.unwrap();
        assert_eq!(resolved.include_topics, ["orders", "events"]);
        assert_eq!(resolved.exclude_topics, ["events"]);
    }
}

#[tokio::test]
async fn restore_topics_and_mappings_accept_all_list_formats() {
    for (included, mappings) in [
        (
            "orders,events",
            " orders : orders-restored, , events:events-restored ",
        ),
        (
            "orders\n events\n",
            "orders:orders-restored\r\n\r\n events:events-restored\r\n",
        ),
        (
            "- orders\n- events\n",
            "- orders:orders-restored\n- ' events:events-restored '\n",
        ),
        (
            "[orders, events]",
            "[orders:orders-restored, events:events-restored]",
        ),
    ] {
        let (client, server) =
            config_map_client(json!({"included": included, "mappings": mappings}));
        let resolved = build_topic_restore_config(
            &vec![],
            &HashMap::new(),
            &restore_config_map().topics_config_map,
            &client,
            "backups",
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(resolved.topics, ["orders", "events"]);
        assert_eq!(
            resolved.topic_mappings,
            HashMap::from([
                ("orders".into(), "orders-restored".into()),
                ("events".into(), "events-restored".into()),
            ])
        );
    }
}

#[tokio::test]
async fn missing_config_map_data_or_keys_still_resolve_to_empty_lists() {
    for data in [Value::Null, json!({}), json!({"unrelated": "orders"})] {
        let (client, server) = config_map_client(data.clone());
        let resolved =
            build_topic_config(&vec![], &vec![], &backup_config_map(), &client, "backups")
                .await
                .unwrap();
        server.await.unwrap();
        assert!(resolved.include_topics.is_empty());
        assert!(resolved.exclude_topics.is_empty());

        let (client, server) = config_map_client(data);
        let resolved = build_topic_restore_config(
            &vec![],
            &HashMap::new(),
            &restore_config_map().topics_config_map,
            &client,
            "backups",
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert!(resolved.topics.is_empty());
        assert!(resolved.topic_mappings.is_empty());
    }
}

fn assert_config_error(error: Error, key: &str) {
    assert!(matches!(error, Error::Config(_)), "{error}");
    let message = error.to_string();
    assert!(message.contains("selection/topic-selection"), "{message}");
    assert!(message.contains(&format!("key '{key}'")), "{message}");
}

#[tokio::test]
async fn backup_reports_yaml_errors_for_both_keys() {
    for key in ["included", "excluded"] {
        let (client, server) = config_map_client(json!({key: "[orders"}));
        let error = build_topic_config(&vec![], &vec![], &backup_config_map(), &client, "backups")
            .await
            .unwrap_err();
        server.await.unwrap();
        assert_config_error(error, key);
    }
}

#[tokio::test]
async fn restore_reports_yaml_errors_and_rejects_mapping_objects() {
    for (key, value) in [
        ("included", "[orders"),
        ("mappings", "[orders:restored"),
        ("mappings", "- orders: restored"),
    ] {
        let (client, server) = config_map_client(json!({key: value}));
        let error = build_topic_restore_config(
            &vec![],
            &HashMap::new(),
            &restore_config_map().topics_config_map,
            &client,
            "backups",
        )
        .await
        .unwrap_err();
        server.await.unwrap();
        assert_config_error(error, key);
    }
}

#[tokio::test]
async fn invalid_mapping_bindings_warn_but_preserve_existing_behavior() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = CapturedOutput(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let (client, server) = config_map_client(json!({
        "mappings": "orders:first,invalid,orders:last, : target,source: ,extra:one:two"
    }));
    let resolved = build_topic_restore_config(
        &vec![],
        &HashMap::new(),
        &restore_config_map().topics_config_map,
        &client,
        "backups",
    )
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(
        resolved.topic_mappings,
        HashMap::from([
            ("orders".into(), "last".into()),
            ("".into(), "target".into()),
            ("source".into(), "".into()),
            ("extra".into(), "one:two".into()),
        ])
    );
    let warnings = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(
        warnings.contains("Skipping invalid topic mapping"),
        "{warnings}"
    );
    assert_eq!(
        warnings.matches("Retaining invalid topic mapping").count(),
        2
    );
    for context in [
        "namespace=\"selection\"",
        "config_map=topic-selection",
        "key=mappings",
    ] {
        assert!(warnings.contains(context), "{warnings}");
    }
}

#[derive(Clone)]
struct CapturedOutput(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
