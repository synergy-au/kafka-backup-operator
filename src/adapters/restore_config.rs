//! Restore configuration adapter
//!
//! Converts KafkaRestore CRD spec to kafka-backup-core configuration.

use k8s_openapi::api::core::v1::ConfigMap;
use kube::{api::Api, Client};
use std::collections::HashMap;
use tracing::{debug, warn};

use crate::crd::{
    BackupRef, HeaderPreflightPolicy, KafkaRestore, OffsetResetSpec, PitrSpec, RollbackSpec,
    TopicRepartitioningSpec, TopicRestoreConfigMap,
};
use crate::error::{Error, Result};

use super::backup_config::{
    build_kafka_config, ResolvedCircuitBreakerConfig, ResolvedKafkaConfig,
    ResolvedRateLimitingConfig,
};
use super::storage_config::{build_storage_config, ResolvedStorage};
use super::topic_config::config_map_list;

/// Fully resolved restore configuration
#[derive(Debug, Clone)]
pub struct ResolvedRestoreConfig {
    /// Source backup location
    pub backup_source: ResolvedBackupSource,
    /// Target Kafka cluster
    pub kafka: ResolvedKafkaConfig,
    /// Topics to restore
    pub topics: Vec<String>,
    /// Topic remapping
    pub topic_mapping: HashMap<String, String>,
    /// Partition remapping
    pub partition_mapping: HashMap<i32, i32>,
    /// Per-topic repartitioning
    pub repartitioning: HashMap<String, ResolvedTopicRepartitioningConfig>,
    /// PITR configuration
    pub pitr: Option<ResolvedPitrConfig>,
    /// Rollback configuration
    pub rollback: Option<ResolvedRollbackConfig>,
    /// Rate limiting
    pub rate_limiting: Option<ResolvedRateLimitingConfig>,
    /// Circuit breaker
    pub circuit_breaker: Option<ResolvedCircuitBreakerConfig>,
    /// Dry run mode
    pub dry_run: bool,
    /// Batch size for producing to target cluster
    pub produce_batch_size: usize,
    /// Producer ack level
    pub produce_acks: i16,
    /// Producer timeout in milliseconds
    pub produce_timeout_ms: i32,
    /// Purge target topics before restore
    pub purge_topics: bool,
    /// Load consumer groups from backup snapshot
    pub auto_consumer_groups: bool,
    /// Post-restore consumer offset reset configuration
    pub offset_reset: Option<ResolvedOffsetResetConfig>,
    /// Create missing topics during restore
    pub create_topics: bool,
    /// Default replication factor for auto-created topics
    pub default_replication_factor: Option<i16>,
    /// Add x-original-* / x-source-partition headers to every restored record
    pub include_original_offset_header: bool,
    /// Strip the headers kafka-backup added at backup time before producing
    pub strip_offset_headers: bool,
    /// Phase 1 header preflight mode
    pub header_preflight: HeaderPreflightPolicy,
}

/// Resolved backup source
#[derive(Debug, Clone)]
pub enum ResolvedBackupSource {
    /// Reference to a KafkaBackup resource
    BackupResource {
        name: String,
        namespace: String,
        backup_id: Option<String>,
    },
    /// Direct storage reference (with optional backup_id from backupRef)
    Storage {
        storage: ResolvedStorage,
        backup_id: Option<String>,
    },
}

/// Resolved PITR configuration
#[derive(Debug, Clone)]
pub struct ResolvedPitrConfig {
    /// Start timestamp in epoch milliseconds
    pub start_timestamp_ms: Option<i64>,
    /// End timestamp in epoch milliseconds
    pub end_timestamp_ms: Option<i64>,
}

/// Resolved rollback configuration
#[derive(Debug, Clone)]
pub struct ResolvedRollbackConfig {
    pub snapshot_before_restore: bool,
    pub snapshot_retention_hours: u32,
    pub auto_rollback_on_failure: bool,
    pub snapshot_path: Option<String>,
}

/// Resolved repartitioning configuration
#[derive(Debug, Clone)]
pub struct ResolvedTopicRepartitioningConfig {
    pub strategy: String,
    pub target_partitions: i32,
}

/// Resolved post-restore offset reset configuration
#[derive(Debug, Clone)]
pub struct ResolvedOffsetResetConfig {
    pub enabled: bool,
    pub consumer_groups: Vec<String>,
    pub strategy: String,
}

#[derive(Debug, Clone)]
pub struct ResolvedTopicRestoreConfig {
    pub topics: Vec<String>,
    pub topic_mappings: std::collections::HashMap<String, String>,
}

/// Build fully resolved topic configuration from deployed CRD resource and ConfigMap (if provided)
pub async fn build_topic_restore_config(
    topics: &Vec<String>,
    topic_mappings: &std::collections::HashMap<String, String>,
    topics_config_map: &Option<TopicRestoreConfigMap>,
    client: &Client,
    namespace: &str,
) -> Result<ResolvedTopicRestoreConfig> {
    debug!(
        topics = ?topics,
        topic_mappings = ?topic_mappings,
        topics_config_map = ?topics_config_map,
        "Building topic config from configuration",
    );
    if !topics_config_map.is_none() && (!topics.is_empty() || !topic_mappings.is_empty()) {
        return Err(Error::Config(
            "Cannot specify 'topics'/'topic_mappings' and 'topics_config_map' simultaneously"
                .to_string(),
        ));
    }
    if let Some(config_map) = topics_config_map {
        let ns: &str = config_map.namespace.as_deref().unwrap_or(namespace);
        let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), ns);
        let config: ConfigMap = config_maps.get(&config_map.name).await?;

        let resolved_included =
            config_map_list(&config, ns, &config_map.name, &config_map.topics_key)?;
        let mapping_entries = config_map_list(
            &config,
            ns,
            &config_map.name,
            &config_map.topic_mappings_key,
        )?;
        let mut resolved_mappings = HashMap::new();
        for (index, mapping) in mapping_entries.iter().enumerate() {
            let Some((source, target)) = mapping.split_once(':') else {
                warn!(
                    namespace = ns,
                    config_map = %config_map.name,
                    key = %config_map.topic_mappings_key,
                    entry = index + 1,
                    "Skipping invalid topic mapping without ':' separator"
                );
                continue;
            };
            let (source, target) = (source.trim(), target.trim());
            if source.is_empty() || target.is_empty() {
                warn!(
                    namespace = ns,
                    config_map = %config_map.name,
                    key = %config_map.topic_mappings_key,
                    entry = index + 1,
                    "Retaining invalid topic mapping with empty source or target for compatibility"
                );
            }
            resolved_mappings.insert(source.to_owned(), target.to_owned());
        }

        let resolved = ResolvedTopicRestoreConfig {
            topics: resolved_included,
            topic_mappings: resolved_mappings,
        };

        Ok(resolved)
    } else if !topics.is_empty() {
        let result: ResolvedTopicRestoreConfig = ResolvedTopicRestoreConfig {
            topics: topics.clone(),
            topic_mappings: topic_mappings.clone(),
        };
        Ok(result)
    } else {
        Err(Error::Config("Either 'topics' or 'topics_config_map' must be specified, but neither have been provided".to_string()))
    }
}

/// Build fully resolved restore configuration from CRD
pub async fn build_restore_config(
    restore: &KafkaRestore,
    client: &Client,
    namespace: &str,
) -> Result<ResolvedRestoreConfig> {
    // Resolve backup source
    let backup_source = resolve_backup_ref(&restore.spec.backup_ref, client, namespace).await?;

    // Resolve Kafka configuration
    let kafka = build_kafka_config(&restore.spec.kafka_cluster, client, namespace).await?;

    // Resolve topic restore configuration
    let topics = build_topic_restore_config(
        &restore.spec.topics,
        &restore.spec.topic_mapping,
        &restore.spec.topics_config_map,
        client,
        namespace,
    )
    .await?;

    debug!(topics = ?topics, "Resolved topic configuration successfully");

    // Build PITR config
    let pitr = restore.spec.pitr.as_ref().map(build_pitr_config);

    // Build rollback config
    let rollback = restore.spec.rollback.as_ref().map(build_rollback_config);

    // Build rate limiting
    let rate_limiting = restore
        .spec
        .rate_limiting
        .as_ref()
        .map(|r| ResolvedRateLimitingConfig {
            records_per_sec: r.records_per_sec,
            bytes_per_sec: r.bytes_per_sec,
            max_concurrent_partitions: r.max_concurrent_partitions,
        });

    // Build circuit breaker
    let circuit_breaker =
        restore
            .spec
            .circuit_breaker
            .as_ref()
            .map(|c| ResolvedCircuitBreakerConfig {
                enabled: c.enabled,
                failure_threshold: c.failure_threshold,
                reset_timeout_secs: c.reset_timeout_secs,
                success_threshold: c.success_threshold,
                operation_timeout_ms: c.operation_timeout_ms,
            });

    Ok(ResolvedRestoreConfig {
        backup_source,
        kafka,
        topics: topics.topics,
        topic_mapping: topics.topic_mappings,
        partition_mapping: restore.spec.partition_mapping.clone(),
        repartitioning: restore
            .spec
            .repartitioning
            .iter()
            .map(|(topic, repartitioning)| {
                (topic.clone(), build_repartitioning_config(repartitioning))
            })
            .collect(),
        pitr,
        rollback,
        rate_limiting,
        circuit_breaker,
        dry_run: restore.spec.dry_run,
        produce_batch_size: restore.spec.produce_batch_size,
        produce_acks: restore.spec.produce_acks,
        produce_timeout_ms: restore.spec.produce_timeout_ms,
        purge_topics: restore.spec.purge_topics,
        auto_consumer_groups: restore.spec.auto_consumer_groups,
        offset_reset: restore
            .spec
            .offset_reset
            .as_ref()
            .map(build_offset_reset_config),
        create_topics: restore.spec.create_topics,
        default_replication_factor: restore.spec.default_replication_factor,
        include_original_offset_header: restore.spec.include_original_offset_header,
        strip_offset_headers: restore.spec.strip_offset_headers,
        header_preflight: restore.spec.header_preflight,
    })
}

/// Resolve backup reference to a concrete source
async fn resolve_backup_ref(
    backup_ref: &BackupRef,
    client: &Client,
    namespace: &str,
) -> Result<ResolvedBackupSource> {
    // If direct storage is specified, use that (preserving backup_id if provided)
    if let Some(storage) = &backup_ref.storage {
        let resolved = build_storage_config(storage, client, namespace).await?;
        return Ok(ResolvedBackupSource::Storage {
            storage: resolved,
            backup_id: backup_ref.backup_id.clone(),
        });
    }

    // Otherwise, reference the KafkaBackup resource
    let backup_namespace = backup_ref
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.to_string());

    Ok(ResolvedBackupSource::BackupResource {
        name: backup_ref.name.clone(),
        namespace: backup_namespace,
        backup_id: backup_ref.backup_id.clone(),
    })
}

fn build_pitr_config(pitr: &PitrSpec) -> ResolvedPitrConfig {
    // Prefer explicit timestamps, fall back to DateTime conversion
    let start_timestamp_ms = pitr
        .start_timestamp
        .or_else(|| pitr.start_time.map(|dt| dt.timestamp_millis()));

    let end_timestamp_ms = pitr
        .end_timestamp
        .or_else(|| pitr.end_time.map(|dt| dt.timestamp_millis()));

    ResolvedPitrConfig {
        start_timestamp_ms,
        end_timestamp_ms,
    }
}

fn build_rollback_config(rollback: &RollbackSpec) -> ResolvedRollbackConfig {
    let snapshot_path = rollback.snapshot_storage.as_ref().map(|s| {
        let base = format!("/snapshots/{}", s.pvc_name);
        match &s.sub_path {
            Some(sub) => format!("{}/{}", base, sub),
            None => base,
        }
    });

    ResolvedRollbackConfig {
        snapshot_before_restore: rollback.snapshot_before_restore,
        snapshot_retention_hours: rollback.snapshot_retention_hours,
        auto_rollback_on_failure: rollback.auto_rollback_on_failure,
        snapshot_path,
    }
}

fn build_repartitioning_config(
    repartitioning: &TopicRepartitioningSpec,
) -> ResolvedTopicRepartitioningConfig {
    ResolvedTopicRepartitioningConfig {
        strategy: repartitioning.strategy.clone(),
        target_partitions: repartitioning.target_partitions,
    }
}

fn build_offset_reset_config(offset_reset: &OffsetResetSpec) -> ResolvedOffsetResetConfig {
    ResolvedOffsetResetConfig {
        enabled: offset_reset.enabled,
        consumer_groups: offset_reset.consumer_groups.clone(),
        strategy: offset_reset.strategy.clone(),
    }
}
