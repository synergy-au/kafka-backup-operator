//! Adapters for converting CRD specs to kafka-backup-core configuration types

mod backup_config;
mod core_integration;
mod evidence;
mod oauth;
mod restore_config;
mod schema_registry;
mod secrets;
mod storage_config;
mod tls_files;
mod validation_config;

pub use backup_config::*;
pub use core_integration::*;
pub use evidence::*;
pub use oauth::*;
pub use restore_config::*;
pub(crate) use schema_registry::registry_object;
pub use schema_registry::ResolvedRegistryConfig;
pub use secrets::*;
pub use storage_config::*;
pub use tls_files::*;
pub use validation_config::*;
