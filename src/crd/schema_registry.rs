use std::{collections::BTreeMap, path::PathBuf};

use kafka_backup_core::oauth::{
    config::{
        AzureManagedIdentityConfig, AzureWorkloadIdentityConfig, CacheConfig, FileProviderConfig,
    },
    http::ClientAuth,
};
use schemars::Schema;
use serde::{Deserialize, Serialize};

pub(super) fn registry_object(_: &mut schemars::SchemaGenerator) -> Schema {
    schemars::json_schema!({"type": "object", "x-kubernetes-preserve-unknown-fields": true})
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum RegistryAuthSpec {
    None,
    Basic {
        username: String,
        password: String,
    },
    #[serde(rename = "mtls")]
    MutualTls {
        client_cert: String,
        client_key: String,
        ca_cert: Option<String>,
    },
    OAuth {
        provider: String,
        target_sr_cluster: Option<String>,
        identity_pool_id: Option<String>,
    },
}

impl std::fmt::Debug for RegistryAuthSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Basic { .. } => "Basic",
            Self::MutualTls { .. } => "MutualTls",
            Self::OAuth { .. } => "OAuth",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryOauthSpec {
    /// Named OAuth providers. The registry auth block selects one by name.
    #[serde(default)]
    #[schemars(schema_with = "provider_map")]
    pub providers: BTreeMap<String, RegistryProviderSpec>,
    /// Upstream token cache settings.
    #[serde(default, skip_serializing_if = "cache_is_default")]
    #[schemars(schema_with = "registry_object")]
    pub cache: CacheConfig,
}

fn cache_is_default(cache: &CacheConfig) -> bool {
    cache.refresh_fraction.is_none()
        && cache.refresh_before_expiry.is_none()
        && cache.clock_skew.is_none()
        && cache.min_refresh_interval.is_none()
}

fn provider_map(_: &mut schemars::SchemaGenerator) -> Schema {
    schemars::json_schema!({
        "type": "object",
        "additionalProperties": {"type": "object", "x-kubernetes-preserve-unknown-fields": true}
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RegistryProviderSpec {
    OidcClientCredentials(RegistryOidcSpec),
    AzureManagedIdentity(AzureManagedIdentityConfig),
    AzureWorkloadIdentity(AzureWorkloadIdentityConfig),
    File(FileProviderConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryOidcSpec {
    pub token_endpoint_url: Option<String>,
    pub issuer: Option<String>,
    pub client_id: String,
    pub client_secret_file: PathBuf,
    #[serde(default)]
    pub client_auth: ClientAuth,
    pub scope: Option<String>,
    pub audience: Option<String>,
    #[serde(default)]
    pub extra_params: BTreeMap<String, String>,
    pub ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub allow_insecure_http: bool,
}
