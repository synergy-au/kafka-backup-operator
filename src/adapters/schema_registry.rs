//! Schema Registry adapter for the Kafka Backup Operator.
//!
//! Handles resolution of schema registry specific configuration.

use std::path::Path;

use kafka_backup_core::{
    oauth::{config::OauthConfig, Secret},
    schema_registry::{SchemaRegistryAuth, SchemaRegistryConfig, SchemaRegistryOAuth},
};
use serde::{Deserialize, Serialize};

use super::oauth::{checked_file, read_credential_file, OauthSpec};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RegistryAuthSpec {
    None,
    Basic {
        #[serde(rename = "usernameFilePath")]
        username_file_path: String,
        #[serde(rename = "passwordFilePath")]
        password_file_path: String,
    },
    #[serde(rename = "mtls")]
    MutualTls {
        client_cert: String,
        client_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca_cert: Option<String>,
    },
    #[serde(rename = "oauth")]
    OAuth(SchemaRegistryOAuth),
}

pub(crate) fn registry_auth_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    // Enforce that mounted file paths have at least two path components (e.g., /<namespace>/<file>)
    let mounted_path = "^/[^/]+/.+";
    schemars::json_schema!({
        "type": "object",
        "required": ["type"],
        "properties": {
            "type": {"type": "string", "enum": ["none", "basic", "mtls", "oauth"]},
            "usernameFilePath": {"type": "string", "pattern": mounted_path, "description": "Mounted file containing the Basic username."},
            "passwordFilePath": {"type": "string", "pattern": mounted_path, "description": "Mounted file containing the Basic password."},
            "client_cert": {"type": "string", "pattern": mounted_path, "description": "Mounted PEM client certificate path."},
            "client_key": {"type": "string", "pattern": mounted_path, "description": "Mounted PEM client private key path."},
            "ca_cert": {"type": "string", "pattern": mounted_path, "description": "Optional mounted PEM CA certificate path."},
            "provider": {"type": "string"},
            "target_sr_cluster": {"type": "string"},
            "identity_pool_id": {"type": "string"}
        },
        "x-kubernetes-validations": [
            {
                "rule": "self.type == 'basic' ? has(self.usernameFilePath) && has(self.passwordFilePath) : !has(self.usernameFilePath) && !has(self.passwordFilePath)",
                "message": "usernameFilePath and passwordFilePath are required and only valid for Basic authentication"
            },
            {
                "rule": "self.type == 'mtls' ? has(self.client_cert) && has(self.client_key) : !has(self.client_cert) && !has(self.client_key) && !has(self.ca_cert)",
                "message": "client_cert and client_key are required for mTLS; these fields and ca_cert are only valid for mTLS"
            },
            {
                "rule": "self.type == 'oauth' ? has(self.provider) : !has(self.provider) && !has(self.target_sr_cluster) && !has(self.identity_pool_id)",
                "message": "provider is required for OAuth; OAuth binding fields are only valid for OAuth"
            }
        ]
    })
}

#[derive(Debug, Clone)]
pub struct ResolvedRegistryConfig {
    pub registry: SchemaRegistryConfig,
    pub oauth: Option<OauthConfig>,
}

pub(super) async fn resolve_registry(
    registry: SchemaRegistryConfig,
    auth: Option<&RegistryAuthSpec>,
    oauth: Option<&OauthSpec>,
    namespace: &str,
) -> Result<ResolvedRegistryConfig> {
    let root = Path::new("/etc/kafka-backup-operator/registry").join(namespace);
    resolve_registry_from_mount(registry, auth, oauth, &root).await
}

async fn resolve_registry_from_mount(
    mut registry: SchemaRegistryConfig,
    auth: Option<&RegistryAuthSpec>,
    oauth: Option<&OauthSpec>,
    root: &Path,
) -> Result<ResolvedRegistryConfig> {
    if let Some(path) = registry.tls.as_ref().and_then(|tls| tls.ca_cert.as_deref()) {
        checked_file(root, Path::new(path)).await?;
    }

    let (auth, oauth) = match auth {
        None => (None, None),
        Some(RegistryAuthSpec::None) => (Some(SchemaRegistryAuth::None), None),
        Some(RegistryAuthSpec::Basic {
            username_file_path,
            password_file_path,
        }) => {
            let username = read_credential_file(
                root,
                Path::new(username_file_path),
                "Schema Registry Basic usernameFilePath",
            )
            .await?;
            let password = read_credential_file(
                root,
                Path::new(password_file_path),
                "Schema Registry Basic passwordFilePath",
            )
            .await?;
            (
                Some(SchemaRegistryAuth::Basic {
                    username,
                    password: Secret::new(password),
                }),
                None,
            )
        }
        Some(RegistryAuthSpec::MutualTls {
            client_cert,
            client_key,
            ca_cert,
        }) => {
            checked_file(root, Path::new(client_cert)).await?;
            checked_file(root, Path::new(client_key)).await?;
            if let Some(path) = ca_cert {
                checked_file(root, Path::new(path)).await?;
            }
            (
                Some(SchemaRegistryAuth::MutualTls {
                    client_cert: client_cert.clone(),
                    client_key: client_key.clone(),
                    ca_cert: ca_cert.clone(),
                }),
                None,
            )
        }
        Some(RegistryAuthSpec::OAuth(binding)) => {
            let oauth = oauth.ok_or_else(|| {
                Error::config("Schema Registry OAuth requires spec.oauth.providers")
            })?;
            (
                Some(SchemaRegistryAuth::OAuth(binding.clone())),
                Some(oauth.resolve_provider(&binding.provider, root).await?),
            )
        }
    };
    registry.auth = auth;
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
    async fn basic_reads_mounted_credentials_and_rejects_empty_or_missing_files() {
        let mount = tempfile::tempdir().unwrap();
        let root = mount.path().canonicalize().unwrap();
        let username = root.join("username");
        let password = root.join("password");
        let auth = serde_json::from_value(json!({
            "type": "basic",
            "usernameFilePath": username,
            "passwordFilePath": password
        }))
        .unwrap();
        let resolve = || {
            resolve_registry_from_mount(
                SchemaRegistryConfig::new("https://registry.example"),
                Some(&auth),
                None,
                &root,
            )
        };
        tokio::fs::write(&username, "test-user\r\n").await.unwrap();
        assert!(resolve()
            .await
            .unwrap_err()
            .to_string()
            .contains("Cannot resolve registry credential path"));
        tokio::fs::write(&password, " \n").await.unwrap();
        assert!(resolve()
            .await
            .unwrap_err()
            .to_string()
            .contains("passwordFilePath is empty"));
        tokio::fs::write(&password, "test-password\n")
            .await
            .unwrap();
        let resolved = resolve().await.unwrap();
        assert!(
            matches!(resolved.registry.auth, Some(SchemaRegistryAuth::Basic { username, password })
            if username == "test-user" && password.expose() == "test-password")
        );
        assert!(resolved.oauth.is_none());
    }

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
        let auth = RegistryAuthSpec::OAuth(
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

    #[tokio::test]
    async fn mtls_passes_validated_paths_to_core() {
        let mount = tempfile::tempdir().unwrap();
        let root = mount.path().canonicalize().unwrap();
        let cert = root.join("client.crt");
        let key = root.join("client.key");
        let ca = root.join("ca.crt");
        for path in [&cert, &key, &ca] {
            tokio::fs::write(path, "").await.unwrap();
        }
        let auth = serde_json::from_value(json!({
            "type": "mtls",
            "client_cert": cert,
            "client_key": key,
            "ca_cert": ca
        }))
        .unwrap();
        let resolved = resolve_registry_from_mount(
            SchemaRegistryConfig::new("https://registry.example"),
            Some(&auth),
            None,
            &root,
        )
        .await
        .unwrap();
        assert!(
            matches!(resolved.registry.auth, Some(SchemaRegistryAuth::MutualTls {
            client_cert, client_key, ca_cert: Some(ca_cert),
        }) if Path::new(&client_cert) == cert && Path::new(&client_key) == key && Path::new(&ca_cert) == ca)
        );
    }
}
