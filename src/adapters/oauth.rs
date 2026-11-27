//! OAuth adapter config specifications for the Kafka backup operator.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use crate::adapters::convert_struct_to_crd_json_schema;
use crate::{Error, Result};
use kafka_backup_core::oauth::{
    config::normalise_pool_list, framing::validate_extension, http::ClientAuth, CacheConfig,
    ClusterBinding, OauthConfig, OidcProviderConfig, ProviderConfig, SaslExtensions, Secret,
};
use schemars::{JsonSchema, Schema};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OauthSpec {
    /// Named OIDC providers selected by Kafka cluster or Schema Registry authentication.
    #[serde(default)]
    pub providers: BTreeMap<String, OperatorOidcProviderConfig>,
    /// Token cache timing settings. Uses humantime durations (`30s`, `5m`, etc.).
    #[serde(default, skip_serializing_if = "cache_is_default")]
    #[schemars(schema_with = "convert_struct_to_crd_json_schema")]
    pub cache: CacheConfig,
}

/// `source.security.oauth` / `target.security.oauth`: which provider a
/// cluster authenticates with, and the SASL extensions sent with its tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OauthClusterBinding {
    /// A key of `oauth.providers`.
    pub provider: String,
    /// RFC 7628 SASL extensions sent with the token.
    #[serde(default)]
    pub extensions: OauthSaslExtensions,
}

impl From<&OauthClusterBinding> for ClusterBinding {
    fn from(binding: &OauthClusterBinding) -> Self {
        Self {
            provider: binding.provider.clone(),
            extensions: SaslExtensions {
                logical_cluster: binding.extensions.logical_cluster.clone(),
                identity_pool_id: binding.extensions.identity_pool_id.clone(),
            },
        }
    }
}

/// The SASL extensions Confluent Cloud understands. Both are optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OauthSaslExtensions {
    /// The Kafka cluster ID (`lkc-...`).
    #[serde(
        rename = "logicalCluster",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub logical_cluster: Option<String>,
    /// The identity pool ID (`pool-...`), or a comma-separated list.
    #[serde(
        rename = "identityPoolId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_pool_id: Option<String>,
}

impl OauthSaslExtensions {
    /// The extensions as sent: empty values dropped, a pool list normalised
    /// to `pool-a,pool-b`, every value checked against RFC 7628.
    pub fn to_map(&self) -> std::result::Result<BTreeMap<String, String>, String> {
        let mut map = BTreeMap::new();
        if let Some(cluster) = self.logical_cluster.as_deref().map(str::trim) {
            if !cluster.is_empty() {
                map.insert("logicalCluster".to_string(), cluster.to_string());
            }
        }
        if let Some(pools) = &self.identity_pool_id {
            let list = normalise_pool_list(pools);
            if !list.is_empty() {
                map.insert("identityPoolId".to_string(), list);
            }
        }
        for (k, v) in &map {
            validate_extension(k, v)?;
        }
        Ok(map)
    }
}

pub(crate) fn broker_oauth_schema(_: &mut schemars::SchemaGenerator) -> Schema {
    schemars::json_schema!({
        "type": "object",
        "required": ["provider"],
        "properties": {
            "provider": {"type": "string", "minLength": 1},
            "extensions": {
                "type": "object",
                "properties": {
                    "logicalCluster": {"type": "string"},
                    "identityPoolId": {"type": "string"}
                }
            }
        }
    })
}

impl OauthSpec {
    pub(super) async fn resolve_provider(&self, name: &str) -> Result<OauthConfig> {
        let spec = self.providers.get(name).ok_or_else(|| {
            Error::config(format!(
                "OAuth provider '{name}' is not defined in spec.oauth.providers"
            ))
        })?;
        let client_id =
            read_credential_file(&spec.client_id_file_path, "OAuth clientIdFilePath").await?;
        let client_secret = Secret::new(
            read_credential_file(&spec.client_secret_file_path, "OAuth clientSecretFilePath")
                .await?,
        );
        if let Some(path) = spec.ca_cert.as_deref() {
            validate_credential_file(path, "OAuth caCert").await?;
        }
        let provider = ProviderConfig::OidcClientCredentials(OidcProviderConfig {
            token_endpoint_url: spec.token_endpoint_url.clone(),
            issuer: spec.issuer.clone(),
            client_id,
            client_secret,
            client_auth: spec.client_auth,
            scope: spec.scope.clone(),
            audience: spec.audience.clone(),
            extra_params: spec.extra_params.clone(),
            ca_cert: spec.ca_cert.clone(),
            allow_insecure_http: spec.allow_insecure_http,
        });
        Ok(OauthConfig {
            providers: [(name.to_owned(), provider)].into(),
            cache: self.cache.clone(),
        })
    }
}

fn cache_is_default(cache: &CacheConfig) -> bool {
    cache.refresh_fraction.is_none()
        && cache.refresh_before_expiry.is_none()
        && cache.clock_skew.is_none()
        && cache.min_refresh_interval.is_none()
}

fn client_auth_schema(_: &mut schemars::SchemaGenerator) -> Schema {
    schemars::json_schema!({"type": "string", "enum": ["basic", "post"]})
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OperatorOidcProviderConfig {
    /// The token endpoint. Set exactly one of `tokenEndpointUrl` and `issuer`.
    #[serde(default)]
    pub token_endpoint_url: Option<String>,
    /// OIDC issuer; the token endpoint is discovered from `{issuer}/.well-known/openid-configuration`.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Path to the file containing the client ID.
    pub client_id_file_path: PathBuf,
    /// Path to the file containing the client secret.
    pub client_secret_file_path: PathBuf,
    /// `basic` (default) or `post` client authentication.
    #[serde(default)]
    #[schemars(schema_with = "client_auth_schema")]
    pub client_auth: ClientAuth,
    /// OAuth scope to request. Optional.
    #[serde(default)]
    pub scope: Option<String>,
    /// Sent as the `audience` parameter (Okta, Auth0). Entra uses `scope`.
    #[serde(default)]
    pub audience: Option<String>,
    /// Extra form parameters for the token request.
    #[serde(default)]
    pub extra_params: BTreeMap<String, String>,
    /// Extra CA certificate (PEM) for a private identity provider.
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    /// Allow `http://` to a non-loopback host. Client secrets then travel in
    /// clear text; for isolated test networks only.
    #[serde(default)]
    pub allow_insecure_http: bool,
}

pub(super) async fn read_credential_file(path: &Path, field: &str) -> Result<String> {
    validate_credential_file(path, field).await?;
    let mut value = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| Error::config(format!("Cannot read {field}: {e}")))?;
    value.truncate(value.trim_end_matches(['\r', '\n']).len());
    if value.trim().is_empty() {
        return Err(Error::config(format!("{field} is empty")));
    }
    Ok(value)
}

pub(super) async fn validate_credential_file(path: &Path, field: &str) -> Result<()> {
    if !path.is_absolute() {
        return Err(Error::config(format!(
            "{field} must be an absolute file path"
        )));
    }
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|e| Error::config(format!("Cannot access {field}: {e}")))?;
    if !metadata.is_file() {
        return Err(Error::config(format!(
            "{field} must point to a regular file"
        )));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn oidc_reads_both_mounted_credentials_for_only_the_selected_provider() {
        let mount = tempfile::tempdir().unwrap();
        let root = mount.path().canonicalize().unwrap();
        let client_id = root.join("client-id");
        let client_secret = root.join("client-secret");
        let oauth: OauthSpec = serde_json::from_value(json!({
            "providers": {
                "registry": {
                    "tokenEndpointUrl": "https://issuer.example/token",
                    "clientIdFilePath": client_id,
                    "clientSecretFilePath": client_secret,
                    "clientAuth": "post"
                },
                "unused": {
                    "clientIdFilePath": "/outside/client-id",
                    "clientSecretFilePath": "/outside/client-secret"
                }
            },
            "cache": {"refresh_fraction": 0.65}
        }))
        .unwrap();
        tokio::fs::write(&client_id, "test-client\r\n")
            .await
            .unwrap();
        tokio::fs::write(&client_secret, "test-secret\n")
            .await
            .unwrap();

        let resolved = oauth.resolve_provider("registry").await.unwrap();
        assert_eq!(resolved.providers.len(), 1);
        let Some(ProviderConfig::OidcClientCredentials(provider)) =
            resolved.providers.get("registry")
        else {
            panic!("OIDC provider expected");
        };
        assert_eq!(provider.client_id, "test-client");
        assert_eq!(provider.client_secret.expose(), "test-secret");
        assert_eq!(provider.client_auth, ClientAuth::Post);
        assert_eq!(resolved.cache.refresh_fraction, Some(0.65));

        for (path, field, original) in [
            (&client_id, "clientIdFilePath", "test-client\r\n"),
            (&client_secret, "clientSecretFilePath", "test-secret\n"),
        ] {
            tokio::fs::write(path, " \r\n").await.unwrap();
            let error = oauth.resolve_provider("registry").await.unwrap_err();
            assert!(error
                .to_string()
                .contains(&format!("OAuth {field} is empty")));
            tokio::fs::write(path, original).await.unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn configured_absolute_paths_can_follow_projected_secret_symlinks() {
        let mount = tempfile::tempdir().unwrap();
        let root = mount.path().join("credentials");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(mount.path().join("current"), "test\n").unwrap();
        let projected = root.join("projected");
        std::os::unix::fs::symlink("../current", &projected).unwrap();
        assert_eq!(
            read_credential_file(&projected, "credential")
                .await
                .unwrap(),
            "test"
        );
        assert!(validate_credential_file(&root, "credential").await.is_err());
    }
}
