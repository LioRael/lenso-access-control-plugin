//! PostgreSQL-backed independent Access Control Plugin.

mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod storage;

use std::{cell::RefCell, fmt, rc::Rc, time::Duration};

use lenso::prelude::*;
use lenso_capability_access_control as access_control;
use lenso_capability_access_control::{
    CheckPermissionError, CheckPermissionRequest, CheckPermissionResponse,
};
use lenso_capability_access_control_admin as admin;
use lenso_capability_access_control_admin::{
    AssignRoleError, AssignRoleRequest, AssignRoleResponse, BootstrapScopeError,
    BootstrapScopeRequest, BootstrapScopeResponse, CreateRoleError, CreateRoleRequest,
    CreateRoleResponse, DeleteRoleError, DeleteRoleRequest, DeleteRoleResponse, RevokeRoleError,
    RevokeRoleRequest, RevokeRoleResponse, SetRolePermissionsError, SetRolePermissionsRequest,
    SetRolePermissionsResponse,
};
use lenso_capability_access_control_directory as directory;
use lenso_capability_access_control_directory::{
    GetRoleError, GetRoleRequest, GetRoleResponse, ListRolesError, ListRolesRequest,
    ListRolesResponse, ListSubjectRolesError, ListSubjectRolesRequest, ListSubjectRolesResponse,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub use operator::{AccessControlOperator, AccessControlOperatorError};

use lenso_access_control_core::valid_secret_reference;
pub use lenso_access_control_core::{
    BINDINGS_MANAGE_PERMISSION, BOOTSTRAP_ROLE_ID, ROLES_MANAGE_PERMISSION,
};
const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);

/// Immutable configuration for one `PostgreSQL` Access Control Instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessControlConfig {
    schema: String,
    database_url_secret: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    bootstrap_callers: Vec<String>,
    #[serde(default)]
    directory_callers: Vec<String>,
}

impl AccessControlConfig {
    /// Creates and validates one Access Control Instance configuration.
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        auth_issuer: impl Into<String>,
        auth_assertion_public_key: impl Into<String>,
        bootstrap_callers: Vec<String>,
    ) -> Result<Self, AccessControlConfigError> {
        let config = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            auth_issuer: auth_issuer.into(),
            auth_assertion_public_key: auth_assertion_public_key.into(),
            bootstrap_callers,
            directory_callers: Vec::new(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Adds the exact peer Plugin Instance keys admitted to directory reads.
    pub fn with_directory_callers(
        mut self,
        directory_callers: Vec<String>,
    ) -> Result<Self, AccessControlConfigError> {
        self.directory_callers = directory_callers;
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), AccessControlConfigError> {
        schema::schema_plan(self.schema.clone())
            .map_err(|_| AccessControlConfigError::InvalidSchema)?;
        if !valid_secret_reference(&self.database_url_secret) {
            return Err(AccessControlConfigError::InvalidSecretReference);
        }
        self.policy()
            .validate()
            .map_err(AccessControlConfigError::from)
    }

    fn policy(&self) -> lenso_access_control_core::PolicyConfig {
        lenso_access_control_core::PolicyConfig {
            auth_issuer: self.auth_issuer.clone(),
            auth_assertion_public_key: self.auth_assertion_public_key.clone(),
            bootstrap_callers: self.bootstrap_callers.clone(),
            directory_callers: self.directory_callers.clone(),
        }
    }
}

/// Invalid immutable Access Control configuration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AccessControlConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database URL secret reference")]
    InvalidSecretReference,
    #[error("invalid Auth issuer")]
    InvalidAuthIssuer,
    #[error("invalid Auth assertion public key")]
    InvalidAuthPublicKey,
    #[error("bootstrap_callers must contain between 1 and 64 valid Instance keys")]
    InvalidBootstrapCallers,
    #[error("bootstrap_callers must not contain duplicates")]
    DuplicateBootstrapCaller,
    #[error("directory_callers must contain at most 64 valid Instance keys")]
    InvalidDirectoryCallers,
    #[error("directory_callers must not contain duplicates")]
    DuplicateDirectoryCaller,
}

fn validate_config(config: &AccessControlConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Access Control configuration is invalid: {error}"),
        })
}

#[derive(Clone, Debug)]
struct PreparedAccessControl {
    postgres: OwnedPostgres,
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "config.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct PostgresAccessControlPlugin {
    #[config]
    config: AccessControlConfig,
    secrets: Port<secrets::SecretsClient>,
    prepared: Rc<RefCell<Option<PreparedAccessControl>>>,
}

impl fmt::Debug for PostgresAccessControlPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresAccessControlPlugin")
            .field("prepared", &self.prepared.borrow().is_some())
            .field("schema", &self.config.schema)
            .field(
                "bootstrap_caller_count",
                &self.config.bootstrap_callers.len(),
            )
            .field(
                "directory_caller_count",
                &self.config.directory_callers.len(),
            )
            .finish_non_exhaustive()
    }
}

#[lenso::provides(
    access_control::AccessControl,
    admin::AccessControlAdmin,
    directory::AccessControlDirectory
)]
impl PostgresAccessControlPlugin {}

impl PostgresAccessControlPlugin {
    async fn check_permission(
        &self,
        context: Ctx,
        request: CheckPermissionRequest,
    ) -> PluginResult<CheckPermissionResponse, CheckPermissionError> {
        self.service().check_permission(context, request).await
    }
    async fn get_role(
        &self,
        context: Ctx,
        request: GetRoleRequest,
    ) -> PluginResult<GetRoleResponse, GetRoleError> {
        self.service().get_role(context, request).await
    }
    async fn list_roles(
        &self,
        context: Ctx,
        request: ListRolesRequest,
    ) -> PluginResult<ListRolesResponse, ListRolesError> {
        self.service().list_roles(context, request).await
    }
    async fn list_subject_roles(
        &self,
        context: Ctx,
        request: ListSubjectRolesRequest,
    ) -> PluginResult<ListSubjectRolesResponse, ListSubjectRolesError> {
        self.service().list_subject_roles(context, request).await
    }
    async fn bootstrap_scope(
        &self,
        context: Ctx,
        request: BootstrapScopeRequest,
    ) -> PluginResult<BootstrapScopeResponse, BootstrapScopeError> {
        self.service().bootstrap_scope(context, request).await
    }
    async fn create_role(
        &self,
        context: Ctx,
        request: CreateRoleRequest,
    ) -> PluginResult<CreateRoleResponse, CreateRoleError> {
        self.service().create_role(context, request).await
    }
    async fn set_role_permissions(
        &self,
        context: Ctx,
        request: SetRolePermissionsRequest,
    ) -> PluginResult<SetRolePermissionsResponse, SetRolePermissionsError> {
        self.service().set_role_permissions(context, request).await
    }
    async fn delete_role(
        &self,
        context: Ctx,
        request: DeleteRoleRequest,
    ) -> PluginResult<DeleteRoleResponse, DeleteRoleError> {
        self.service().delete_role(context, request).await
    }
    async fn assign_role(
        &self,
        context: Ctx,
        request: AssignRoleRequest,
    ) -> PluginResult<AssignRoleResponse, AssignRoleError> {
        self.service().assign_role(context, request).await
    }
    async fn revoke_role(
        &self,
        context: Ctx,
        request: RevokeRoleRequest,
    ) -> PluginResult<RevokeRoleResponse, RevokeRoleError> {
        self.service().revoke_role(context, request).await
    }
    fn service(&self) -> lenso_access_control_core::AccessControl<storage::PostgresStore> {
        let postgres = self.prepared.borrow().as_ref().map(|p| p.postgres.clone());
        lenso_access_control_core::AccessControl::new(
            self.config.policy(),
            storage::PostgresStore(postgres),
        )
    }
}

impl Lifecycle for PostgresAccessControlPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let database_url = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        self.prepared
            .borrow_mut()
            .replace(PreparedAccessControl { postgres });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

async fn resolve_secret(
    secrets: &SecretsClient,
    dependencies: &PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("database URL secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

impl From<lenso_access_control_core::PolicyError> for AccessControlConfigError {
    fn from(error: lenso_access_control_core::PolicyError) -> Self {
        match error {
            lenso_access_control_core::PolicyError::InvalidAuthIssuer => Self::InvalidAuthIssuer,
            lenso_access_control_core::PolicyError::InvalidAuthPublicKey => {
                Self::InvalidAuthPublicKey
            }
            lenso_access_control_core::PolicyError::InvalidBootstrapCallers => {
                Self::InvalidBootstrapCallers
            }
            lenso_access_control_core::PolicyError::DuplicateBootstrapCaller => {
                Self::DuplicateBootstrapCaller
            }
            lenso_access_control_core::PolicyError::InvalidDirectoryCallers => {
                Self::InvalidDirectoryCallers
            }
            lenso_access_control_core::PolicyError::DuplicateDirectoryCaller => {
                Self::DuplicateDirectoryCaller
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_app_plan::{AppComposition, PluginInstancePlan};
    use lenso_auth_sdk::ActorAssertionIssuer;
    use lenso_kernel::{CancellationToken, InvocationContext};
    use lenso_native_adapter::NativePluginRegistry;
    use std::collections::BTreeSet;

    fn config() -> AccessControlConfig {
        let issuer = ActorAssertionIssuer::new("auth.users", b"access-control-test-key");
        AccessControlConfig::new(
            "access_control",
            "access-control/database-url",
            "auth.users",
            issuer.public_key_base64(),
            vec!["organization-provisioner".to_owned()],
        )
        .unwrap()
        .with_directory_callers(vec!["access-request".to_owned()])
        .unwrap()
    }

    fn context(caller: &str) -> InvocationContext {
        InvocationContext::new(1, None, CancellationToken::new()).with_caller_instance(caller)
    }

    fn plugin() -> PostgresAccessControlPlugin {
        PostgresAccessControlPlugin {
            config: config(),
            secrets: Port::default(),
            prepared: Rc::new(RefCell::new(None)),
        }
    }

    #[test]
    fn descriptor_and_factory_are_macro_generated() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(descriptor["plugin_id"], "lenso.access-control.postgres");
        let provided = descriptor["provided_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            provided,
            BTreeSet::from([
                access_control::CAPABILITY_ID,
                admin::CAPABILITY_ID,
                directory::CAPABILITY_ID,
            ])
        );
        assert_eq!(
            descriptor["required_capabilities"][0]["capability_id"],
            secrets::CAPABILITY_ID
        );
        assert_eq!(
            NativePluginRegistry::new()
                .with_linked_factories()
                .factories()
                .filter(|factory| factory.package_id() == PACKAGE_ID)
                .count(),
            1
        );
    }

    #[test]
    fn config_rejects_ambient_or_duplicate_bootstrap_authority() {
        let mut invalid = config();
        invalid.bootstrap_callers.clear();
        assert_eq!(
            invalid.validate(),
            Err(AccessControlConfigError::InvalidBootstrapCallers)
        );
        let mut invalid = config();
        invalid
            .bootstrap_callers
            .push("organization-provisioner".to_owned());
        assert_eq!(
            invalid.validate(),
            Err(AccessControlConfigError::DuplicateBootstrapCaller)
        );

        let mut invalid = config();
        invalid.directory_callers.push("access-request".to_owned());
        assert_eq!(
            invalid.validate(),
            Err(AccessControlConfigError::DuplicateDirectoryCaller)
        );
    }

    #[test]
    fn bootstrap_requires_the_exact_configured_caller_before_storage() {
        let result = futures::executor::block_on(plugin().bootstrap_scope(
            context("another-plugin"),
            BootstrapScopeRequest {
                scope: admin::BootstrapScopeRequestScope {
                    kind: "organization".to_owned(),
                    id: "org_42".to_owned(),
                },
                subject: "usr_owner".to_owned(),
            },
        ));
        assert_eq!(
            result,
            Err(PluginError::Domain(BootstrapScopeError::Forbidden))
        );
    }

    #[test]
    fn post_bootstrap_admin_requires_an_actor_assertion_before_storage() {
        let result = futures::executor::block_on(plugin().create_role(
            context("organization-api"),
            CreateRoleRequest {
                scope: admin::CreateRoleRequestScope {
                    kind: "organization".to_owned(),
                    id: "org_42".to_owned(),
                },
                role_id: "viewer".to_owned(),
                name: "Viewer".to_owned(),
            },
        ));
        assert_eq!(
            result,
            Err(PluginError::Domain(CreateRoleError::Unauthenticated))
        );
    }

    #[test]
    fn directory_reads_require_the_exact_configured_caller_before_storage() {
        let result = futures::executor::block_on(plugin().get_role(
            context("another-plugin"),
            GetRoleRequest {
                role_id: "viewer".to_owned(),
                scope: directory::Scope {
                    id: "org_42".to_owned(),
                    kind: "organization".to_owned(),
                },
            },
        ));
        assert_eq!(result, Err(PluginError::Domain(GetRoleError::Forbidden)));
    }

    #[test]
    fn directory_pages_validate_before_storage() {
        let roles = futures::executor::block_on(plugin().list_roles(
            context("access-request"),
            ListRolesRequest {
                cursor: None,
                limit: 0,
                scope: directory::Scope {
                    id: "org_42".to_owned(),
                    kind: "organization".to_owned(),
                },
            },
        ));
        assert_eq!(roles, Err(PluginError::Domain(ListRolesError::InvalidPage)));

        let subject_roles = futures::executor::block_on(plugin().list_subject_roles(
            context("access-request"),
            ListSubjectRolesRequest {
                cursor: None,
                limit: 10,
                scope: directory::Scope {
                    id: "org_42".to_owned(),
                    kind: "organization".to_owned(),
                },
                subject: "invalid subject".to_owned(),
            },
        ));
        assert_eq!(
            subject_roles,
            Err(PluginError::Domain(ListSubjectRolesError::InvalidRequest))
        );
    }

    #[test]
    fn removing_access_control_leaves_scope_owners_resolvable() {
        let remaining = AppComposition::new(
            vec![PluginInstancePlan::new(
                "organization",
                "lenso.organization.postgres",
            )],
            vec![],
        )
        .resolve()
        .expect("scope owner does not require Access Control when RBAC is removed");
        assert_eq!(remaining.plugin_instances().len(), 1);
        assert!(remaining.capability_bindings().is_empty());
    }
}
