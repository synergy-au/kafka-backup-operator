use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

use kafka_backup_core::{
    oauth::{
        config::{
            AzureManagedIdentityConfig, AzureWorkloadIdentityConfig, CacheConfig,
            FileProviderConfig, OauthConfig, OidcProviderConfig, ProviderConfig, Secret,
        },
        http::ClientAuth,
    },
    schema_registry::{SchemaRegistryAuth, SchemaRegistryConfig},
};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{Error, Result};

pub(crate) fn registry_object(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "object", "x-kubernetes-preserve-unknown-fields": true})
}

/// Adds nested provider definitions to core's provider-name authentication binding.
#[derive(Debug, Clone, Serialize)]
pub struct RegistryAuthSpec {
    #[serde(flatten)]
    pub auth: SchemaRegistryAuth,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub providers: BTreeMap<String, RegistryProviderSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheConfig>,
}

impl<'de> Deserialize<'de> for RegistryAuthSpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            #[serde(flatten)]
            auth: SchemaRegistryAuth,
            providers: Option<BTreeMap<String, RegistryProviderSpec>>,
            cache: Option<CacheConfig>,
        }

        let wire = Wire::deserialize(deserializer)?;
        if !matches!(&wire.auth, SchemaRegistryAuth::OAuth(_))
            && (wire.providers.is_some() || wire.cache.is_some())
        {
            return Err(serde::de::Error::custom(
                "Schema Registry providers and cache are only valid for auth type oauth",
            ));
        }
        Ok(Self {
            auth: wire.auth,
            providers: wire.providers.unwrap_or_default(),
            cache: wire.cache,
        })
    }
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

#[derive(Debug, Clone)]
pub struct ResolvedRegistryConfig {
    pub registry: SchemaRegistryConfig,
    pub oauth: Option<OauthConfig>,
}

pub(super) async fn resolve_registry(
    mut registry: SchemaRegistryConfig,
    auth: Option<&RegistryAuthSpec>,
    namespace: &str,
) -> Result<ResolvedRegistryConfig> {
    let root = Path::new("/etc/kafka-backup-operator/registry").join(namespace);
    if let Some(path) = registry.tls.as_mut().and_then(|tls| tls.ca_cert.as_mut()) {
        *path = checked_file(&root, Path::new(path))
            .await?
            .display()
            .to_string();
    }

    let mut resolved_oauth = None;
    registry.auth = match auth {
        None => None,
        Some(spec) => Some(match &spec.auth {
            SchemaRegistryAuth::None | SchemaRegistryAuth::Basic { .. } => spec.auth.clone(),
            SchemaRegistryAuth::MutualTls {
                client_cert,
                client_key,
                ca_cert,
            } => SchemaRegistryAuth::MutualTls {
                client_cert: checked_file(&root, Path::new(client_cert))
                    .await?
                    .display()
                    .to_string(),
                client_key: checked_file(&root, Path::new(client_key))
                    .await?
                    .display()
                    .to_string(),
                ca_cert: match ca_cert {
                    Some(path) => Some(
                        checked_file(&root, Path::new(path))
                            .await?
                            .display()
                            .to_string(),
                    ),
                    None => None,
                },
            },
            SchemaRegistryAuth::OAuth(binding) => {
                let provider = &binding.provider;
                let selected = spec.providers.get(provider).ok_or_else(|| {
                    Error::config(format!(
                        "Schema Registry OAuth provider '{provider}' is not defined in schemaRegistry.auth.providers"
                    ))
                })?;
                resolved_oauth = Some(OauthConfig {
                    providers: [(provider.clone(), resolve_provider(selected, &root).await?)]
                        .into(),
                    cache: spec.cache.clone().unwrap_or_default(),
                });
                SchemaRegistryAuth::OAuth(binding.clone())
            }
            _ => {
                return Err(Error::config(
                    "Unsupported Schema Registry authentication type",
                ))
            }
        }),
    };
    Ok(ResolvedRegistryConfig {
        registry,
        oauth: resolved_oauth,
    })
}

async fn resolve_provider(provider: &RegistryProviderSpec, root: &Path) -> Result<ProviderConfig> {
    Ok(match provider {
        RegistryProviderSpec::OidcClientCredentials(spec) => {
            let path = checked_file(root, &spec.client_secret_file).await?;
            let value = tokio::fs::read_to_string(path)
                .await
                .map_err(|e| Error::config(format!("Cannot read OAuth client_secret_file: {e}")))?;
            let client_secret = Secret::new(value.trim_end_matches(['\r', '\n']));
            if client_secret.is_empty() {
                return Err(Error::config("OAuth client_secret_file is empty"));
            }
            ProviderConfig::OidcClientCredentials(OidcProviderConfig {
                token_endpoint_url: spec.token_endpoint_url.clone(),
                issuer: spec.issuer.clone(),
                client_id: spec.client_id.clone(),
                client_secret,
                client_auth: spec.client_auth,
                scope: spec.scope.clone(),
                audience: spec.audience.clone(),
                extra_params: spec.extra_params.clone(),
                ca_cert: checked_optional_file(root, spec.ca_cert.as_deref()).await?,
                allow_insecure_http: spec.allow_insecure_http,
            })
        }
        RegistryProviderSpec::AzureManagedIdentity(spec) => {
            ProviderConfig::AzureManagedIdentity(spec.clone())
        }
        RegistryProviderSpec::AzureWorkloadIdentity(spec) => {
            let mut spec = spec.clone();
            spec.token_file = checked_optional_file(root, spec.token_file.as_deref()).await?;
            ProviderConfig::AzureWorkloadIdentity(spec)
        }
        RegistryProviderSpec::File(spec) => {
            let mut spec = spec.clone();
            spec.path = checked_file(root, &spec.path).await?;
            spec.expires_at_file =
                checked_optional_file(root, spec.expires_at_file.as_deref()).await?;
            ProviderConfig::File(spec)
        }
    })
}

async fn checked_optional_file(root: &Path, path: Option<&Path>) -> Result<Option<PathBuf>> {
    match path {
        Some(path) => checked_file(root, path).await.map(Some),
        None => Ok(None),
    }
}

async fn checked_file(root: &Path, path: &Path) -> Result<PathBuf> {
    let invalid = || {
        Error::config(format!(
            "Registry credential path must name a file under {}",
            root.display()
        ))
    };
    let relative = path.strip_prefix(root).map_err(|_| invalid())?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err(invalid());
    }
    let canonical = tokio::fs::canonicalize(path)
        .await
        .map_err(|e| Error::config(format!("Cannot resolve registry credential path: {e}")))?;
    if !canonical.starts_with(root) || !tokio::fs::metadata(&canonical).await?.is_file() {
        return Err(invalid());
    }
    // Keep the mounted path so providers that refresh tokens see Secret volume rotations.
    Ok(path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn oauth_resolves_only_the_selected_provider_and_preserves_binding() {
        let auth = serde_json::from_value(json!({
            "type": "oauth",
            "provider": "registry",
            "providers": {
                "registry": {
                    "type": "azure_managed_identity",
                    "resource": "api://registry"
                },
                "unused": {"type": "file", "path": "/outside/token"}
            },
            "cache": {"refresh_fraction": 0.65},
            "target_sr_cluster": "lsrc-test",
            "identity_pool_id": "pool-test"
        }))
        .unwrap();

        let resolved = resolve_registry(
            SchemaRegistryConfig::new("https://registry.example"),
            Some(&auth),
            "default",
        )
        .await
        .unwrap();

        let Some(SchemaRegistryAuth::OAuth(binding)) = resolved.registry.auth else {
            panic!("OAuth registry binding expected");
        };
        assert_eq!(binding.provider, "registry");
        assert_eq!(binding.target_sr_cluster.as_deref(), Some("lsrc-test"));
        assert_eq!(binding.identity_pool_id.as_deref(), Some("pool-test"));
        let oauth = resolved.oauth.unwrap();
        assert_eq!(oauth.providers.len(), 1);
        assert_eq!(oauth.cache.refresh_fraction, Some(0.65));
        assert!(matches!(
            oauth.providers.get("registry"),
            Some(ProviderConfig::AzureManagedIdentity(provider))
                if provider.resource.as_deref() == Some("api://registry")
        ));
    }

    #[tokio::test]
    async fn oauth_rejects_missing_or_undefined_providers() {
        for providers in [
            json!({}),
            json!({"other": {"type": "azure_managed_identity"}}),
        ] {
            let auth = serde_json::from_value(json!({
                "type": "oauth", "provider": "missing", "providers": providers
            }))
            .unwrap();
            let error = resolve_registry(
                SchemaRegistryConfig::new("https://registry.example"),
                Some(&auth),
                "default",
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("provider 'missing' is not defined in schemaRegistry.auth.providers"),
                "{error}"
            );
        }
    }

    #[test]
    fn auth_rejects_oauth_fields_for_other_auth_types_and_unknown_settings() {
        for invalid in [
            json!({"type": "none", "providers": {}}),
            json!({"type": "basic", "username": "user", "password": "secret", "cache": {}}),
            json!({"type": "oauth", "provider": "registry", "providerz": {}}),
            json!({
                "type": "oauth", "provider": "registry",
                "providers": {"registry": {"type": "static", "token": "secret"}}
            }),
            json!({
                "type": "oauth", "provider": "registry",
                "providers": {"registry": {
                    "type": "oidc_client_credentials", "client_id": "operator",
                    "client_secret": "inline-secret"
                }}
            }),
            json!({
                "type": "oauth", "provider": "registry",
                "providers": {"registry": {
                    "type": "azure_managed_identity", "resorce": "api://registry"
                }}
            }),
        ] {
            assert!(
                serde_json::from_value::<RegistryAuthSpec>(invalid.clone()).is_err(),
                "unexpectedly accepted {invalid}"
            );
        }
    }

    #[tokio::test]
    async fn mtls_rejects_credentials_outside_the_namespace_mount() {
        let auth = serde_json::from_value(json!({
            "type": "mtls",
            "client_cert": "/outside/client.crt",
            "client_key": "/outside/client.key"
        }))
        .unwrap();
        let error = resolve_registry(
            SchemaRegistryConfig::new("https://registry.example"),
            Some(&auth),
            "default",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(
            "Registry credential path must name a file under /etc/kafka-backup-operator/registry/default"
        ));
    }

    #[tokio::test]
    async fn oidc_uses_mounted_credentials_and_rejects_empty_files() {
        let mount = tempfile::tempdir().unwrap();
        let root = mount.path().canonicalize().unwrap();
        let path = root.join("client-secret");
        let spec = serde_json::from_value(serde_json::json!({
            "type": "oidc_client_credentials",
            "token_endpoint_url": "https://issuer.example/token",
            "client_id": "operator",
            "client_secret_file": path,
        }))
        .unwrap();
        tokio::fs::write(&path, "test-secret\n").await.unwrap();
        let ProviderConfig::OidcClientCredentials(provider) =
            resolve_provider(&spec, &root).await.unwrap()
        else {
            panic!("OIDC provider expected");
        };
        assert_eq!(provider.client_secret.expose(), "test-secret");
        tokio::fs::write(&path, "\n").await.unwrap();
        assert!(resolve_provider(&spec, &root)
            .await
            .unwrap_err()
            .to_string()
            .contains("client_secret_file is empty"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn projected_secret_paths_stay_inside_the_namespace_mount() {
        let mount = tempfile::tempdir().unwrap();
        let root = mount.path().canonicalize().unwrap().join("namespace");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("current"), "test").unwrap();
        std::fs::write(root.join("../outside"), "test").unwrap();
        let projected = root.join("projected");
        std::os::unix::fs::symlink("current", &projected).unwrap();
        assert_eq!(checked_file(&root, &projected).await.unwrap(), projected);
        std::os::unix::fs::symlink("../outside", root.join("escape")).unwrap();
        assert!(checked_file(&root, &root.join("escape")).await.is_err());
    }
}
