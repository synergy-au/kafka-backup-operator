//! Schema Registry adapter for the Kafka Backup Operator.
//!
//! Handles resolution of schema registry specific configuration.

use std::path::Path;

use kafka_backup_core::{
    oauth::config::OauthConfig,
    schema_registry::{SchemaRegistryAuth, SchemaRegistryConfig},
};

use super::oauth::{checked_file, OauthSpec};
use crate::error::{Error, Result};

pub(crate) fn registry_object(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "object", "x-kubernetes-preserve-unknown-fields": true})
}

#[derive(Debug, Clone)]
pub struct ResolvedRegistryConfig {
    pub registry: SchemaRegistryConfig,
    pub oauth: Option<OauthConfig>,
}

pub(super) async fn resolve_registry(
    registry: SchemaRegistryConfig,
    auth: Option<&SchemaRegistryAuth>,
    oauth: Option<&OauthSpec>,
    namespace: &str,
) -> Result<ResolvedRegistryConfig> {
    let root = Path::new("/etc/kafka-backup-operator/registry").join(namespace);
    resolve_registry_from_mount(registry, auth, oauth, &root).await
}

async fn resolve_registry_from_mount(
    mut registry: SchemaRegistryConfig,
    auth: Option<&SchemaRegistryAuth>,
    oauth: Option<&OauthSpec>,
    root: &Path,
) -> Result<ResolvedRegistryConfig> {
    if let Some(path) = registry.tls.as_ref().and_then(|tls| tls.ca_cert.as_deref()) {
        checked_file(root, Path::new(path)).await?;
    }

    let oauth = match auth {
        None | Some(SchemaRegistryAuth::None | SchemaRegistryAuth::Basic { .. }) => None,
        Some(SchemaRegistryAuth::MutualTls {
            client_cert,
            client_key,
            ca_cert,
        }) => {
            checked_file(root, Path::new(client_cert)).await?;
            checked_file(root, Path::new(client_key)).await?;
            if let Some(path) = ca_cert {
                checked_file(root, Path::new(path)).await?;
            }
            None
        }
        Some(SchemaRegistryAuth::OAuth(binding)) => {
            let oauth = oauth.ok_or_else(|| {
                Error::config("Schema Registry OAuth requires spec.oauth.providers")
            })?;
            Some(oauth.resolve_provider(&binding.provider, root).await?)
        }
        Some(_) => {
            return Err(Error::config(
                "Unsupported Schema Registry authentication type",
            ));
        }
    };
    registry.auth = auth.cloned();
    Ok(ResolvedRegistryConfig { registry, oauth })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kafka_backup_core::{
        config::Config,
        oauth::{http::ClientAuth, ProviderConfig},
    };
    use serde_json::json;

    #[tokio::test]
    async fn oauth_loads_the_selected_mounted_credentials_and_installs_the_binding() {
        crate::install_crypto_provider();
        let mount = tempfile::tempdir().unwrap();
        let root = mount.path().canonicalize().unwrap();
        let client_id = root.join("client-id");
        let client_secret = root.join("client-secret");
        let oauth = serde_json::from_value(json!({
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
            "cache": {"refresh_fraction": 0.65, "clock_skew": "7s"}
        }))
        .unwrap();
        let auth = serde_json::from_value(json!({
            "type": "oauth",
            "provider": "registry",
            "target_sr_cluster": "lsrc-test",
            "identity_pool_id": "pool-test"
        }))
        .unwrap();
        tokio::fs::write(&client_id, "test-client\r\n")
            .await
            .unwrap();
        tokio::fs::write(&client_secret, "test-secret\n")
            .await
            .unwrap();

        let resolve = || {
            resolve_registry_from_mount(
                SchemaRegistryConfig::new("https://registry.example"),
                Some(&auth),
                Some(&oauth),
                &root,
            )
        };
        let resolved = resolve().await.unwrap();
        let mut core: Config = serde_json::from_value(json!({
            "mode": "backup",
            "backup_id": "test",
            "storage": {"backend": "memory"}
        }))
        .unwrap();
        crate::adapters::configure_registry(&mut core, Some(&resolved)).unwrap();
        let Some(SchemaRegistryAuth::OAuth(binding)) = core.schema_registry.unwrap().auth else {
            panic!("OAuth registry binding expected");
        };
        assert_eq!(binding.provider, "registry");
        assert_eq!(binding.target_sr_cluster.as_deref(), Some("lsrc-test"));
        assert_eq!(binding.identity_pool_id.as_deref(), Some("pool-test"));
        assert!(binding.token_source.is_some());

        let oauth = core.oauth.unwrap();
        assert_eq!(oauth.providers.len(), 1);
        let Some(ProviderConfig::OidcClientCredentials(provider)) = oauth.providers.get("registry")
        else {
            panic!("OIDC provider expected");
        };
        assert_eq!(provider.client_id, "test-client");
        assert_eq!(provider.client_secret.expose(), "test-secret");
        assert_eq!(provider.client_auth, ClientAuth::Post);
        assert_eq!(oauth.cache.refresh_fraction, Some(0.65));
        assert_eq!(oauth.cache.clock_skew.unwrap().as_secs(), 7);

        for (path, field, original) in [
            (&client_id, "clientIdFilePath", "test-client\r\n"),
            (&client_secret, "clientSecretFilePath", "test-secret\n"),
        ] {
            tokio::fs::write(path, " \r\n").await.unwrap();
            let error = resolve().await.unwrap_err();
            assert!(error
                .to_string()
                .contains(&format!("OAuth {field} is empty")));
            tokio::fs::write(path, original).await.unwrap();
        }
    }

    #[tokio::test]
    async fn oauth_rejects_missing_or_undefined_providers() {
        let auth = SchemaRegistryAuth::OAuth(
            kafka_backup_core::schema_registry::SchemaRegistryOAuth::new("missing"),
        );
        let oauth = serde_json::from_value(json!({})).unwrap();
        for (spec, expected) in [
            (None, "requires spec.oauth.providers"),
            (
                Some(&oauth),
                "provider 'missing' is not defined in spec.oauth.providers",
            ),
        ] {
            let error = resolve_registry(
                SchemaRegistryConfig::new("https://registry.example"),
                Some(&auth),
                spec,
                "default",
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
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
            None,
            "default",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(
            "Registry credential path must name a file under /etc/kafka-backup-operator/registry/default"
        ));
    }
}
