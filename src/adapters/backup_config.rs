//! Backup configuration adapter
//!
//! Converts KafkaBackup CRD spec to kafka-backup-core configuration.

use kafka_backup_core::{oauth::OauthConfig, schema_registry::SchemaRegistryConfig};
use kube::Client;
use std::path::Path;

use crate::crd::{
    CheckpointSpec, CircuitBreakerSpec, KafkaBackup, KafkaBackupSpec, KafkaClusterSpec,
    KafkaConnectionSpec, MetricsSpec, OnMissingTopicPolicy, RateLimitingSpec,
};
use crate::error::{Error, Result};

use super::oauth::{credential_root, OauthClusterBinding, OauthSpec};
use super::schema_registry::{resolve_registry, ResolvedRegistryConfig};
use super::secrets::{get_sasl_credentials, get_tls_credentials_split, TlsCredentials};
use super::storage_config::{build_storage_config, ResolvedStorage};

/// Fully resolved backup configuration
#[derive(Debug, Clone)]
pub struct ResolvedBackupConfig {
    pub schema_registry: Option<ResolvedRegistryConfig>,
    /// Kafka cluster configuration
    pub kafka: ResolvedKafkaConfig,
    /// Topics to backup
    pub topics: Vec<String>,
    /// Topics to leave out
    pub exclude_topics: Vec<String>,
    /// Storage configuration
    pub storage: ResolvedStorage,
    /// Compression settings
    pub compression: CompressionConfig,
    /// Checkpoint settings
    pub checkpoint: Option<ResolvedCheckpointConfig>,
    /// Rate limiting settings
    pub rate_limiting: Option<ResolvedRateLimitingConfig>,
    /// Circuit breaker settings
    pub circuit_breaker: Option<ResolvedCircuitBreakerConfig>,
    /// Metrics settings
    pub metrics: Option<ResolvedMetricsConfig>,
    /// Backup segment and mode settings
    pub backup_options: ResolvedBackupOptionsConfig,
}

/// Resolved Kafka cluster configuration with credentials
#[derive(Debug, Clone)]
pub struct ResolvedKafkaConfig {
    pub bootstrap_servers: Vec<String>,
    pub security_protocol: String,
    pub tls: Option<TlsCredentials>,
    pub sasl: Option<SaslCredentials>,
    pub oauth: Option<ResolvedBrokerOauth>,
    pub connection: ResolvedKafkaConnectionConfig,
}

#[derive(Debug, Clone)]
pub struct ResolvedBrokerOauth {
    pub binding: OauthClusterBinding,
    pub config: OauthConfig,
}

/// Resolved Kafka connection tuning
#[derive(Debug, Clone)]
pub struct ResolvedKafkaConnectionConfig {
    pub tcp_keepalive: bool,
    pub keepalive_time_secs: u64,
    pub keepalive_interval_secs: u64,
    pub tcp_nodelay: bool,
    pub connections_per_broker: usize,
    pub produce_api_version: Option<i16>,
    pub fetch_max_wait_ms: i32,
}

impl Default for ResolvedKafkaConnectionConfig {
    fn default() -> Self {
        Self {
            tcp_keepalive: true,
            keepalive_time_secs: 60,
            keepalive_interval_secs: 20,
            tcp_nodelay: true,
            connections_per_broker: 4,
            produce_api_version: None,
            fetch_max_wait_ms: 500,
        }
    }
}

/// SASL credentials
#[derive(Debug, Clone)]
pub struct SaslCredentials {
    pub mechanism: String,
    pub username: String,
    pub password: String,
}

/// Compression configuration
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    pub algorithm: String,
    pub level: i32,
}

/// Resolved checkpoint configuration
#[derive(Debug, Clone)]
pub struct ResolvedCheckpointConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub storage_path: Option<String>,
}

/// Resolved rate limiting configuration
#[derive(Debug, Clone)]
pub struct ResolvedRateLimitingConfig {
    pub records_per_sec: u64,
    pub bytes_per_sec: u64,
    pub max_concurrent_partitions: usize,
}

/// Resolved circuit breaker configuration
#[derive(Debug, Clone)]
pub struct ResolvedCircuitBreakerConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub reset_timeout_secs: u64,
    pub success_threshold: u32,
    pub operation_timeout_ms: u64,
}

/// Resolved metrics configuration
#[derive(Debug, Clone)]
pub struct ResolvedMetricsConfig {
    pub enabled: bool,
    pub port: u16,
    pub bind_address: String,
    pub path: String,
    pub update_interval_ms: u64,
    pub max_partition_labels: usize,
}

/// Resolved backup behavior and tuning options
#[derive(Debug, Clone)]
pub struct ResolvedBackupOptionsConfig {
    pub segment_max_bytes: u64,
    pub segment_max_interval_ms: u64,
    pub continuous: bool,
    pub stop_at_current_offsets: bool,
    pub include_offset_headers: bool,
    pub source_cluster_id: Option<String>,
    pub poll_interval_ms: u64,
    pub empty_fetch_retry_secs: u64,
    pub consumer_group_snapshot: bool,
    pub on_missing_topic: OnMissingTopicPolicy,
}

pub(crate) async fn resolve_backup_registry(
    spec: &KafkaBackupSpec,
    namespace: &str,
) -> Result<Option<ResolvedRegistryConfig>> {
    let Some(section) = spec.schema_registry.as_ref().filter(|s| s.enabled) else {
        return Ok(None);
    };
    let mut registry = SchemaRegistryConfig::new(&section.url);
    registry.tls = section.tls.clone();
    registry.connection = section.connection.clone();
    registry.backup = section.backup_options.clone();
    if registry
        .backup_options()
        .snapshot_interval_or_default()
        .is_zero()
    {
        return Err(Error::config(
            "Schema Registry snapshot_interval must be greater than zero",
        ));
    }
    resolve_registry(
        registry,
        section.auth.as_ref(),
        spec.oauth.as_ref(),
        namespace,
    )
    .await
    .map(Some)
}

/// Build fully resolved backup configuration from CRD
pub async fn build_backup_config(
    backup: &KafkaBackup,
    client: &Client,
    namespace: &str,
) -> Result<ResolvedBackupConfig> {
    // Resolve Kafka configuration
    let kafka = build_kafka_config(
        &backup.spec.kafka_cluster,
        backup.spec.oauth.as_ref(),
        client,
        namespace,
    )
    .await?;

    let schema_registry = resolve_backup_registry(&backup.spec, namespace).await?;

    // Resolve storage configuration
    let storage = build_storage_config(&backup.spec.storage, client, namespace).await?;

    // Build compression config
    let compression = CompressionConfig {
        algorithm: backup.spec.compression.clone(),
        level: backup.spec.compression_level,
    };

    // Build checkpoint config
    let checkpoint = backup.spec.checkpoint.as_ref().map(build_checkpoint_config);

    // Build rate limiting config
    let rate_limiting = backup
        .spec
        .rate_limiting
        .as_ref()
        .map(build_rate_limiting_config);

    // Build circuit breaker config
    let circuit_breaker = backup
        .spec
        .circuit_breaker
        .as_ref()
        .map(build_circuit_breaker_config);

    // Build metrics config
    let metrics = backup.spec.metrics.as_ref().map(build_metrics_config);

    let backup_options = ResolvedBackupOptionsConfig {
        segment_max_bytes: backup.spec.segment_max_bytes,
        segment_max_interval_ms: backup.spec.segment_max_interval_ms,
        continuous: backup.spec.continuous,
        stop_at_current_offsets: backup.spec.stop_at_current_offsets,
        include_offset_headers: backup.spec.include_offset_headers,
        source_cluster_id: backup.spec.source_cluster_id.clone(),
        poll_interval_ms: backup.spec.poll_interval_ms,
        empty_fetch_retry_secs: backup.spec.empty_fetch_retry_secs,
        consumer_group_snapshot: backup.spec.consumer_group_snapshot,
        on_missing_topic: backup.spec.on_missing_topic,
    };

    Ok(ResolvedBackupConfig {
        schema_registry,
        kafka,
        topics: backup.spec.topics.clone(),
        exclude_topics: backup.spec.exclude_topics.clone(),
        storage,
        compression,
        checkpoint,
        rate_limiting,
        circuit_breaker,
        metrics,
        backup_options,
    })
}

/// Build Kafka cluster configuration with resolved credentials
pub(crate) fn validate_kafka_auth(
    kafka: &KafkaClusterSpec,
    oauth: Option<&OauthSpec>,
) -> Result<()> {
    let protocol = kafka.security_protocol.to_ascii_uppercase();
    if let Some(binding) = &kafka.oauth {
        if !matches!(protocol.as_str(), "SASL_SSL" | "OAUTHBEARER") {
            return Err(Error::validation(
                "spec.kafkaCluster.oauth requires securityProtocol SASL_SSL or OAUTHBEARER (TLS)",
            ));
        }
        if kafka.sasl_secret.is_some() {
            return Err(Error::validation(
                "spec.kafkaCluster.oauth and spec.kafkaCluster.saslSecret are mutually exclusive",
            ));
        }
        if binding.provider.trim().is_empty() {
            return Err(Error::validation(
                "spec.kafkaCluster.oauth.provider must not be blank",
            ));
        }
        binding.extensions.to_map().map_err(|err| {
            Error::validation(format!("Invalid spec.kafkaCluster.oauth.extensions: {err}"))
        })?;
        if !oauth.is_some_and(|spec| spec.providers.contains_key(&binding.provider)) {
            return Err(Error::validation(format!(
                "spec.kafkaCluster.oauth.provider '{}' is not defined in spec.oauth.providers",
                binding.provider
            )));
        }
    } else {
        if protocol == "OAUTHBEARER"
            || kafka
                .sasl_secret
                .as_ref()
                .is_some_and(|sasl| sasl.mechanism.eq_ignore_ascii_case("OAUTHBEARER"))
        {
            return Err(Error::validation(
                "OAUTHBEARER requires spec.kafkaCluster.oauth, not spec.kafkaCluster.saslSecret",
            ));
        }
        if matches!(protocol.as_str(), "SSL" | "SASL_SSL")
            && kafka.tls_secret.is_none()
            && kafka.ca_secret.is_none()
        {
            return Err(Error::validation(
                "securityProtocol SSL/SASL_SSL requires either tlsSecret or caSecret to be configured",
            ));
        }
    }
    Ok(())
}

pub async fn build_kafka_config(
    kafka: &KafkaClusterSpec,
    oauth: Option<&OauthSpec>,
    client: &Client,
    namespace: &str,
) -> Result<ResolvedKafkaConfig> {
    build_kafka_config_from_mount(kafka, oauth, client, namespace, &credential_root(namespace))
        .await
}

async fn build_kafka_config_from_mount(
    kafka: &KafkaClusterSpec,
    oauth: Option<&OauthSpec>,
    client: &Client,
    namespace: &str,
    root: &Path,
) -> Result<ResolvedKafkaConfig> {
    validate_kafka_auth(kafka, oauth)?;
    let oauth = match (&kafka.oauth, oauth) {
        (Some(binding), Some(spec)) => Some(ResolvedBrokerOauth {
            binding: binding.clone(),
            config: spec
                .resolve_provider(&binding.provider, root)
                .await
                .map_err(|err| Error::config(format!("spec.kafkaCluster.oauth: {err}")))?,
        }),
        _ => None,
    };
    // Resolve TLS credentials if configured
    let has_tls = kafka.tls_secret.is_some();
    let has_ca = kafka.ca_secret.is_some();
    let tls = if has_tls || has_ca {
        Some(
            get_tls_credentials_split(
                client,
                namespace,
                kafka.tls_secret.as_ref().map(|t| t.name.as_str()),
                kafka
                    .tls_secret
                    .as_ref()
                    .map(|t| t.ca_key.as_str())
                    .unwrap_or("ca.crt"),
                kafka
                    .tls_secret
                    .as_ref()
                    .and_then(|t| t.cert_key.as_deref()),
                kafka.tls_secret.as_ref().and_then(|t| t.key_key.as_deref()),
                kafka.ca_secret.as_ref().map(|c| c.name.as_str()),
                kafka.ca_secret.as_ref().map(|c| c.ca_key.as_str()),
            )
            .await?,
        )
    } else {
        None
    };

    // Resolve SASL credentials if configured
    let sasl = if let Some(sasl_ref) = &kafka.sasl_secret {
        let (username, password) = get_sasl_credentials(
            client,
            namespace,
            &sasl_ref.name,
            &sasl_ref.username_key,
            &sasl_ref.password_key,
        )
        .await?;

        Some(SaslCredentials {
            mechanism: sasl_ref.mechanism.clone(),
            username,
            password,
        })
    } else {
        None
    };

    Ok(ResolvedKafkaConfig {
        bootstrap_servers: kafka.bootstrap_servers.clone(),
        security_protocol: kafka.security_protocol.clone(),
        tls,
        sasl,
        oauth,
        connection: kafka
            .connection
            .as_ref()
            .map(build_connection_config)
            .unwrap_or_default(),
    })
}

fn build_connection_config(connection: &KafkaConnectionSpec) -> ResolvedKafkaConnectionConfig {
    ResolvedKafkaConnectionConfig {
        tcp_keepalive: connection.tcp_keepalive,
        keepalive_time_secs: connection.keepalive_time_secs,
        keepalive_interval_secs: connection.keepalive_interval_secs,
        tcp_nodelay: connection.tcp_nodelay,
        connections_per_broker: connection.connections_per_broker,
        produce_api_version: connection.produce_api_version,
        fetch_max_wait_ms: connection.fetch_max_wait_ms,
    }
}

fn build_checkpoint_config(checkpoint: &CheckpointSpec) -> ResolvedCheckpointConfig {
    let storage_path = checkpoint.storage.as_ref().map(|s| {
        let base = format!("/checkpoints/{}", s.pvc_name);
        match &s.sub_path {
            Some(sub) => format!("{}/{}", base, sub),
            None => base,
        }
    });

    ResolvedCheckpointConfig {
        enabled: checkpoint.enabled,
        interval_secs: checkpoint.interval_secs,
        storage_path,
    }
}

fn build_rate_limiting_config(rate_limiting: &RateLimitingSpec) -> ResolvedRateLimitingConfig {
    ResolvedRateLimitingConfig {
        records_per_sec: rate_limiting.records_per_sec,
        bytes_per_sec: rate_limiting.bytes_per_sec,
        max_concurrent_partitions: rate_limiting.max_concurrent_partitions,
    }
}

fn build_circuit_breaker_config(
    circuit_breaker: &CircuitBreakerSpec,
) -> ResolvedCircuitBreakerConfig {
    ResolvedCircuitBreakerConfig {
        enabled: circuit_breaker.enabled,
        failure_threshold: circuit_breaker.failure_threshold,
        reset_timeout_secs: circuit_breaker.reset_timeout_secs,
        success_threshold: circuit_breaker.success_threshold,
        operation_timeout_ms: circuit_breaker.operation_timeout_ms,
    }
}

fn build_metrics_config(metrics: &MetricsSpec) -> ResolvedMetricsConfig {
    ResolvedMetricsConfig {
        enabled: metrics.enabled,
        port: metrics.port,
        bind_address: metrics.bind_address.clone(),
        path: metrics.path.clone(),
        update_interval_ms: metrics.update_interval_ms,
        max_partition_labels: metrics.max_partition_labels,
    }
}

#[cfg(test)]
mod broker_oauth_tests {
    use super::*;
    use crate::adapters::{
        build_restore_config, build_validation_config, to_core_backup_config,
        to_core_restore_config, to_core_target_kafka_config, to_core_validation_config,
    };
    use crate::crd::{
        KafkaBackupValidation, KafkaOffsetResetSpec, KafkaOffsetRollbackSpec, KafkaRestore,
    };
    use kafka_backup_core::{
        config::{KafkaConfig, SaslMechanism, SecurityProtocol},
        oauth::ProviderConfig,
        schema_registry::{SchemaRegistryAuth, SchemaRegistryOAuth},
    };
    use serde_json::{json, Value};

    fn cluster(protocol: &str) -> Value {
        json!({
            "bootstrapServers": ["broker.example:9092"],
            "securityProtocol": protocol,
            "oauth": {
                "provider": "broker",
                "extensions": {"logicalCluster": "lkc-example", "identityPoolId": "pool-example"}
            }
        })
    }

    fn providers(root: &Path) -> Value {
        let provider = json!({
            "tokenEndpointUrl": "https://issuer.example/token",
            "clientIdFilePath": root.join("id"),
            "clientSecretFilePath": root.join("secret")
        });
        json!({
            "providers": {
                "broker": provider,
                "registry": provider,
                "unused": {
                    "clientIdFilePath": "/outside/id",
                    "clientSecretFilePath": "/outside/secret"
                }
            },
            "cache": {"refresh_fraction": 0.75}
        })
    }

    fn assert_installed(kafka: &KafkaConfig) {
        assert!(matches!(
            kafka.security.security_protocol,
            SecurityProtocol::SaslSsl
        ));
        assert!(matches!(
            kafka.security.sasl_mechanism,
            Some(SaslMechanism::OAuthBearer)
        ));
        assert!(kafka.security.sasl_username.is_none());
        assert!(kafka.security.sasl_password.is_none());
        let binding = kafka.security.oauth.as_ref().unwrap();
        assert_eq!(binding.provider, "broker");
        assert_eq!(
            binding.extensions.logical_cluster.as_deref(),
            Some("lkc-example")
        );
        assert_eq!(
            binding.extensions.identity_pool_id.as_deref(),
            Some("pool-example")
        );
        assert_eq!(
            kafka
                .security
                .sasl_mechanism_plugin_factory
                .as_ref()
                .unwrap()
                .mechanism_name(),
            "OAUTHBEARER"
        );
    }

    #[test]
    fn invalid_broker_auth_is_rejected_before_resolving_credentials() {
        let oauth = serde_json::from_value(providers(Path::new("/outside"))).unwrap();
        let no_binding = json!({"bootstrapServers": ["broker"], "securityProtocol": "OAUTHBEARER"});
        let mut blank = cluster("SASL_SSL");
        blank["oauth"]["provider"] = json!(" ");
        let mut conflict = cluster("SASL_SSL");
        conflict["saslSecret"] = json!({"name": "unused", "mechanism": "PLAIN"});
        let oauth_secret = json!({
            "bootstrapServers": ["broker"], "securityProtocol": "SASL_SSL",
            "saslSecret": {"name": "unused", "mechanism": "OAUTHBEARER"}
        });
        for (spec, providers, expected) in [
            (no_binding, Some(&oauth), "requires spec.kafkaCluster.oauth"),
            (
                cluster("SASL_SSL"),
                None,
                "not defined in spec.oauth.providers",
            ),
            (
                cluster("SASL_PLAINTEXT"),
                Some(&oauth),
                "requires securityProtocol SASL_SSL",
            ),
            (blank, Some(&oauth), "must not be blank"),
            (conflict, Some(&oauth), "mutually exclusive"),
            (
                oauth_secret,
                Some(&oauth),
                "requires spec.kafkaCluster.oauth",
            ),
        ] {
            let spec = serde_json::from_value(spec).unwrap();
            let error = validate_kafka_auth(&spec, providers).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[tokio::test]
    async fn mounted_broker_auth_reaches_all_five_core_client_paths() {
        crate::install_crypto_provider();
        let client =
            Client::try_from(kube::Config::new("http://127.0.0.1".parse().unwrap())).unwrap();
        let mount = tempfile::tempdir().unwrap();
        let mount = mount.path().canonicalize().unwrap();
        let storage = json!({"storageType": "pvc", "pvc": {"claimName": "test-pvc"}});
        let broker = cluster("SASL_SSL");
        let oauth_json = providers(&mount);
        let oauth: OauthSpec = serde_json::from_value(oauth_json.clone()).unwrap();
        let broker_spec = serde_json::from_value(broker.clone()).unwrap();
        let error =
            build_kafka_config_from_mount(&broker_spec, Some(&oauth), &client, "test", &mount)
                .await
                .unwrap_err();
        assert!(error.to_string().contains("spec.kafkaCluster.oauth"));
        tokio::fs::write(mount.join("id"), "mounted-client\n")
            .await
            .unwrap();
        tokio::fs::write(mount.join("secret"), "mounted-secret\n")
            .await
            .unwrap();
        let resolved =
            build_kafka_config_from_mount(&broker_spec, Some(&oauth), &client, "test", &mount)
                .await
                .unwrap();

        let mut backup = KafkaBackup::new("test", serde_json::from_value(json!({
            "kafkaCluster": broker, "oauth": oauth_json, "topics": ["orders"], "storage": storage
        })).unwrap());
        let restore = KafkaRestore::new(
            "test",
            serde_json::from_value(json!({
                "kafkaCluster": cluster("OAUTHBEARER"), "oauth": oauth_json,
                "backupRef": {"name": "test"}, "topics": ["orders"]
            }))
            .unwrap(),
        );
        let validation = KafkaBackupValidation::new("test", serde_json::from_value(json!({
            "kafkaCluster": broker, "oauth": oauth_json, "backupRef": {"name": "test"}, "checks": {}
        })).unwrap());
        let reset: KafkaOffsetResetSpec = serde_json::from_value(json!({
            "kafkaCluster": broker, "oauth": oauth_json, "consumerGroups": ["group"],
            "resetStrategy": "to-earliest", "topics": ["orders"]
        }))
        .unwrap();
        let rollback: KafkaOffsetRollbackSpec = serde_json::from_value(json!({
            "kafkaCluster": broker, "oauth": oauth_json, "snapshotRef": {"name": "test"}
        }))
        .unwrap();

        // Production adapters must use the binding and spec.oauth, and refuse files
        // outside the real mount. Use our temporary mount for successful handoffs.
        for error in [
            build_backup_config(&backup, &client, "test")
                .await
                .unwrap_err(),
            build_restore_config(&restore, &client, "test")
                .await
                .unwrap_err(),
            build_validation_config(&validation, &client, "test")
                .await
                .unwrap_err(),
        ] {
            assert!(
                error.to_string().contains("spec.kafkaCluster.oauth"),
                "{error}"
            );
        }
        backup.spec.kafka_cluster.oauth = None;
        backup.spec.kafka_cluster.security_protocol = "PLAINTEXT".into();
        let mut backup = build_backup_config(&backup, &client, "test").await.unwrap();
        backup.kafka = resolved.clone();
        let core = to_core_backup_config(&backup, "test", None).unwrap();
        assert_installed(core.source.as_ref().unwrap());
        let config = core.oauth.unwrap();
        assert_eq!(config.providers.len(), 1);
        let ProviderConfig::OidcClientCredentials(provider) = &config.providers["broker"] else {
            panic!("expected the mounted OIDC provider");
        };
        assert_eq!(provider.client_id, "mounted-client");
        assert_eq!(provider.client_secret.expose(), "mounted-secret");
        assert_eq!(config.cache.refresh_fraction, Some(0.75));

        let mut restore = restore;
        let kafka = build_kafka_config_from_mount(
            &restore.spec.kafka_cluster,
            restore.spec.oauth.as_ref(),
            &client,
            "test",
            &mount,
        )
        .await
        .unwrap();
        restore.spec.kafka_cluster.oauth = None;
        restore.spec.kafka_cluster.security_protocol = "PLAINTEXT".into();
        let mut restore = build_restore_config(&restore, &client, "test")
            .await
            .unwrap();
        restore.kafka = kafka;
        for provider in ["broker", "registry"] {
            let mut registry = SchemaRegistryConfig::new("https://registry.example");
            registry.auth = Some(SchemaRegistryAuth::OAuth(SchemaRegistryOAuth::new(
                provider,
            )));
            restore.schema_registry = Some(ResolvedRegistryConfig {
                registry,
                oauth: Some(oauth.resolve_provider(provider, &mount).await.unwrap()),
            });
            let core = to_core_restore_config(&restore, "test", &backup.storage, None).unwrap();
            assert_installed(core.target.as_ref().unwrap());
            assert_eq!(
                core.oauth.unwrap().providers.len(),
                if provider == "broker" { 1 } else { 2 }
            );
            let Some(SchemaRegistryAuth::OAuth(binding)) = core.schema_registry.unwrap().auth
            else {
                panic!("expected registry OAuth");
            };
            assert_eq!(binding.provider, provider);
            assert!(binding.token_source.is_some());
        }

        let mut validation = validation;
        validation.spec.kafka_cluster = None;
        let mut validation = build_validation_config(&validation, &client, "test")
            .await
            .unwrap();
        validation.kafka = Some(resolved);
        let core = to_core_validation_config(&validation, "test", &backup.storage, None).unwrap();
        assert_installed(&core.target);
        for (cluster, oauth, topics) in [
            (reset.kafka_cluster, reset.oauth, reset.topics),
            (rollback.kafka_cluster, rollback.oauth, vec![]),
        ] {
            let resolved =
                build_kafka_config_from_mount(&cluster, oauth.as_ref(), &client, "test", &mount)
                    .await
                    .unwrap();
            let core = to_core_target_kafka_config(&resolved, &topics, None).unwrap();
            assert_installed(&core);
            assert_eq!(core.topics.include, topics);
        }
    }
}

#[cfg(test)]
mod produce_api_version_tests {
    use super::*;

    fn connection(spec: serde_json::Value) -> ResolvedKafkaConnectionConfig {
        build_connection_config(&serde_json::from_value(spec).unwrap())
    }

    #[test]
    fn unset_by_default() {
        assert_eq!(
            ResolvedKafkaConnectionConfig::default().produce_api_version,
            None
        );
        assert_eq!(connection(serde_json::json!({})).produce_api_version, None);
    }

    /// The CRD schema must reject at admission exactly what core rejects at
    /// validation, so the range is read from core rather than duplicated.
    #[test]
    fn crd_schema_range_matches_core() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(crate::crd::KafkaBackup::crd()).unwrap();
        let field = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
            ["properties"]["kafkaCluster"]["properties"]["connection"]["properties"]
            ["produceApiVersion"];
        let range = kafka_backup_core::config::PRODUCE_API_VERSIONS;
        assert_eq!(
            field["minimum"].as_f64(),
            Some(*range.start() as f64),
            "{field}"
        );
        assert_eq!(
            field["maximum"].as_f64(),
            Some(*range.end() as f64),
            "{field}"
        );
    }

    #[test]
    fn spec_value_reaches_core_config() {
        let resolved = ResolvedKafkaConfig {
            bootstrap_servers: vec!["broker:9092".to_string()],
            security_protocol: "PLAINTEXT".to_string(),
            tls: None,
            sasl: None,
            oauth: None,
            connection: connection(serde_json::json!({ "produceApiVersion": 7 })),
        };
        let core = crate::adapters::core_integration::to_core_connection_config(&resolved);
        assert_eq!(core.produce_api_version, Some(7));
    }
}
