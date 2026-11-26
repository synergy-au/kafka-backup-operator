use std::path::{Component, Path, PathBuf};

use kafka_backup_core::{
    oauth::config::{OauthConfig, OidcProviderConfig, ProviderConfig, Secret},
    schema_registry::{SchemaRegistryAuth, SchemaRegistryConfig, SchemaRegistryOAuth},
};

use crate::{
    crd::{RegistryAuthSpec, RegistryOauthSpec, RegistryProviderSpec},
    error::{Error, Result},
};

#[derive(Debug, Clone)]
pub struct ResolvedRegistryConfig {
    pub registry: SchemaRegistryConfig,
    pub oauth: Option<OauthConfig>,
}

pub(super) async fn resolve_registry(
    mut registry: SchemaRegistryConfig,
    auth: Option<&RegistryAuthSpec>,
    oauth: Option<&RegistryOauthSpec>,
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
        Some(RegistryAuthSpec::None) => Some(SchemaRegistryAuth::None),
        Some(RegistryAuthSpec::Basic { username, password }) => Some(SchemaRegistryAuth::Basic {
            username: username.clone(),
            password: Secret::new(password.clone()),
        }),
        Some(RegistryAuthSpec::MutualTls {
            client_cert,
            client_key,
            ca_cert,
        }) => Some(SchemaRegistryAuth::MutualTls {
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
        }),
        Some(RegistryAuthSpec::OAuth {
            provider,
            target_sr_cluster,
            identity_pool_id,
        }) => {
            let oauth = oauth.ok_or_else(|| {
                Error::config("Schema Registry OAuth requires spec.oauth.providers")
            })?;
            let selected = oauth.providers.get(provider).ok_or_else(|| {
                Error::config(format!(
                    "Schema Registry OAuth provider '{provider}' is not defined"
                ))
            })?;
            resolved_oauth = Some(OauthConfig {
                providers: [(provider.clone(), resolve_provider(selected, &root).await?)].into(),
                cache: oauth.cache.clone(),
            });
            let mut binding = SchemaRegistryOAuth::new(provider);
            binding.target_sr_cluster = target_sr_cluster.clone();
            binding.identity_pool_id = identity_pool_id.clone();
            Some(SchemaRegistryAuth::OAuth(binding))
        }
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
