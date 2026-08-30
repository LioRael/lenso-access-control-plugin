//! PostgreSQL-backed independent Access Control Plugin.

mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod storage;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use lenso::prelude::*;
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock, TypedActor,
};
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
    Role,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::storage::{DomainFailure, Mutation, ScopeKey};

pub use operator::{AccessControlOperator, AccessControlOperatorError};

/// Stable protected role created by `bootstrap_scope`.
pub const BOOTSTRAP_ROLE_ID: &str = "access-control.bootstrap-admin";
/// Permission required to create, replace grants on, or delete ordinary roles.
pub const ROLES_MANAGE_PERMISSION: &str = "access-control.roles.manage";
/// Permission required to assign or revoke scoped role bindings.
pub const BINDINGS_MANAGE_PERMISSION: &str = "access-control.bindings.manage";

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_SCOPE_KIND_BYTES: usize = 128;
const MAX_SCOPE_ID_BYTES: usize = 512;
const MAX_SUBJECT_BYTES: usize = 512;
const MAX_ROLE_ID_BYTES: usize = 128;
const MAX_ROLE_NAME_BYTES: usize = 200;
const MAX_PERMISSION_BYTES: usize = 200;
const MAX_PERMISSIONS_PER_ROLE: usize = 256;
const MAX_BOOTSTRAP_CALLERS: usize = 64;
const MAX_DIRECTORY_CALLERS: usize = 64;

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
        if !valid_identifier(&self.auth_issuer, 256) {
            return Err(AccessControlConfigError::InvalidAuthIssuer);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| AccessControlConfigError::InvalidAuthPublicKey)?;
        if self.bootstrap_callers.is_empty()
            || self.bootstrap_callers.len() > MAX_BOOTSTRAP_CALLERS
            || self
                .bootstrap_callers
                .iter()
                .any(|caller| !valid_identifier(caller, 256))
        {
            return Err(AccessControlConfigError::InvalidBootstrapCallers);
        }
        if self.bootstrap_callers.iter().collect::<BTreeSet<_>>().len()
            != self.bootstrap_callers.len()
        {
            return Err(AccessControlConfigError::DuplicateBootstrapCaller);
        }
        if self.directory_callers.len() > MAX_DIRECTORY_CALLERS
            || self
                .directory_callers
                .iter()
                .any(|caller| !valid_identifier(caller, 256))
        {
            return Err(AccessControlConfigError::InvalidDirectoryCallers);
        }
        if self.directory_callers.iter().collect::<BTreeSet<_>>().len()
            != self.directory_callers.len()
        {
            return Err(AccessControlConfigError::DuplicateDirectoryCaller);
        }
        Ok(())
    }

    fn verifier(&self) -> Result<ActorAssertionVerifier, RuntimeFailure> {
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "Access Control Auth verification key is invalid".to_owned(),
        })
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
        _context: Ctx,
        request: CheckPermissionRequest,
    ) -> PluginResult<CheckPermissionResponse, CheckPermissionError> {
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        if !valid_scope(&scope)
            || !valid_subject(&request.subject)
            || !valid_permission(&request.permission)
        {
            return Err(PluginError::domain(CheckPermissionError::InvalidRequest));
        }
        let decision = storage::check_permission(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            &request.subject,
            &request.permission,
        )
        .await
        .map_err(|error| storage_runtime(&error))?;
        Ok(CheckPermissionResponse {
            allowed: decision.allowed,
            policy_revision: revision_string(decision.revision)?,
        })
    }

    async fn get_role(
        &self,
        context: Ctx,
        request: GetRoleRequest,
    ) -> PluginResult<GetRoleResponse, GetRoleError> {
        if !self.directory_authorized(&context) {
            return Err(PluginError::domain(GetRoleError::Forbidden));
        }
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        if !valid_scope(&scope) || !valid_role_id(&request.role_id) {
            return Err(PluginError::domain(GetRoleError::InvalidRequest));
        }
        let (role, revision) = storage::get_role(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            &request.role_id,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .map_err(|failure| PluginError::domain(map_get_role_failure(failure)))?;
        Ok(GetRoleResponse {
            name: role.name,
            permissions: role.permissions,
            policy_revision: revision_string(revision)?,
            protected: role.protected,
            role_id: role.role_id,
        })
    }

    async fn list_roles(
        &self,
        context: Ctx,
        request: ListRolesRequest,
    ) -> PluginResult<ListRolesResponse, ListRolesError> {
        if !self.directory_authorized(&context) {
            return Err(PluginError::domain(ListRolesError::Forbidden));
        }
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        if !valid_scope(&scope) {
            return Err(PluginError::domain(ListRolesError::InvalidRequest));
        }
        let Some(limit) = valid_directory_page(request.limit, request.cursor.as_deref()) else {
            return Err(PluginError::domain(ListRolesError::InvalidPage));
        };
        let page = storage::list_roles(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            request.cursor.as_deref(),
            limit,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .map_err(|failure| PluginError::domain(map_list_roles_failure(failure)))?;
        let roles = page
            .roles
            .into_iter()
            .map(directory_role)
            .collect::<Vec<_>>();
        let next_cursor = page.has_more.then(|| {
            roles
                .last()
                .expect("non-empty truncated page")
                .role_id
                .clone()
        });
        Ok(ListRolesResponse {
            next_cursor,
            policy_revision: revision_string(page.revision)?,
            roles,
        })
    }

    async fn list_subject_roles(
        &self,
        context: Ctx,
        request: ListSubjectRolesRequest,
    ) -> PluginResult<ListSubjectRolesResponse, ListSubjectRolesError> {
        if !self.directory_authorized(&context) {
            return Err(PluginError::domain(ListSubjectRolesError::Forbidden));
        }
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        if !valid_scope(&scope) || !valid_subject(&request.subject) {
            return Err(PluginError::domain(ListSubjectRolesError::InvalidRequest));
        }
        let Some(limit) = valid_directory_page(request.limit, request.cursor.as_deref()) else {
            return Err(PluginError::domain(ListSubjectRolesError::InvalidPage));
        };
        let page = storage::list_subject_roles(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            &request.subject,
            request.cursor.as_deref(),
            limit,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .map_err(|failure| PluginError::domain(map_list_subject_roles_failure(failure)))?;
        let roles = page
            .roles
            .into_iter()
            .map(directory_role)
            .collect::<Vec<_>>();
        let next_cursor = page.has_more.then(|| {
            roles
                .last()
                .expect("non-empty truncated page")
                .role_id
                .clone()
        });
        Ok(ListSubjectRolesResponse {
            next_cursor,
            policy_revision: revision_string(page.revision)?,
            roles,
            subject: request.subject,
        })
    }

    async fn bootstrap_scope(
        &self,
        context: Ctx,
        request: BootstrapScopeRequest,
    ) -> PluginResult<BootstrapScopeResponse, BootstrapScopeError> {
        if !self.bootstrap_authorized(&context) {
            return Err(PluginError::domain(BootstrapScopeError::Forbidden));
        }
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        if !valid_scope(&scope) || !valid_subject(&request.subject) {
            return Err(PluginError::domain(BootstrapScopeError::InvalidRequest));
        }
        let outcome = storage::bootstrap_scope(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            &request.subject,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .map_err(|failure| PluginError::domain(map_bootstrap_failure(failure)))?;
        Ok(BootstrapScopeResponse {
            created: outcome.created,
            role_id: BOOTSTRAP_ROLE_ID.to_owned(),
            policy_revision: revision_string(outcome.revision)?,
        })
    }

    async fn create_role(
        &self,
        context: Ctx,
        request: CreateRoleRequest,
    ) -> PluginResult<CreateRoleResponse, CreateRoleError> {
        let actor = self
            .authenticated_subject(&context, admin::CREATE_ROLE_OPERATION)
            .map_err(|()| PluginError::domain(CreateRoleError::Unauthenticated))?;
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        if !valid_scope(&scope)
            || !valid_role_id(&request.role_id)
            || request.role_id == BOOTSTRAP_ROLE_ID
            || !valid_display_name(&request.name)
        {
            return Err(PluginError::domain(CreateRoleError::InvalidRequest));
        }
        let mutation = storage::create_role(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            &actor,
            &request.role_id,
            &request.name,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .map_err(|failure| PluginError::domain(map_create_role_failure(failure)))?;
        create_role_response(mutation)
    }

    async fn set_role_permissions(
        &self,
        context: Ctx,
        request: SetRolePermissionsRequest,
    ) -> PluginResult<SetRolePermissionsResponse, SetRolePermissionsError> {
        let actor = self
            .authenticated_subject(&context, admin::SET_ROLE_PERMISSIONS_OPERATION)
            .map_err(|()| PluginError::domain(SetRolePermissionsError::Unauthenticated))?;
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        let permission_count = request.permissions.len();
        let permissions = request.permissions.into_iter().collect::<BTreeSet<_>>();
        if !valid_scope(&scope)
            || !valid_role_id(&request.role_id)
            || permission_count != permissions.len()
            || permissions.len() > MAX_PERMISSIONS_PER_ROLE
            || permissions.iter().any(|value| !valid_permission(value))
        {
            return Err(PluginError::domain(SetRolePermissionsError::InvalidRequest));
        }
        let mutation = storage::set_role_permissions(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            &actor,
            &request.role_id,
            &permissions,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .map_err(|failure| PluginError::domain(map_set_permissions_failure(failure)))?;
        Ok(SetRolePermissionsResponse {
            changed: mutation.changed,
            policy_revision: revision_string(mutation.revision)?,
        })
    }

    async fn delete_role(
        &self,
        context: Ctx,
        request: DeleteRoleRequest,
    ) -> PluginResult<DeleteRoleResponse, DeleteRoleError> {
        let actor = self
            .authenticated_subject(&context, admin::DELETE_ROLE_OPERATION)
            .map_err(|()| PluginError::domain(DeleteRoleError::Unauthenticated))?;
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        if !valid_scope(&scope) || !valid_role_id(&request.role_id) {
            return Err(PluginError::domain(DeleteRoleError::InvalidRequest));
        }
        let mutation = storage::delete_role(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            &actor,
            &request.role_id,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .map_err(|failure| PluginError::domain(map_delete_role_failure(failure)))?;
        Ok(DeleteRoleResponse {
            changed: mutation.changed,
            policy_revision: revision_string(mutation.revision)?,
        })
    }

    async fn assign_role(
        &self,
        context: Ctx,
        request: AssignRoleRequest,
    ) -> PluginResult<AssignRoleResponse, AssignRoleError> {
        let actor = self
            .authenticated_subject(&context, admin::ASSIGN_ROLE_OPERATION)
            .map_err(|()| PluginError::domain(AssignRoleError::Unauthenticated))?;
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        if !valid_scope(&scope)
            || !valid_subject(&request.subject)
            || !valid_role_id(&request.role_id)
        {
            return Err(PluginError::domain(AssignRoleError::InvalidRequest));
        }
        let mutation = storage::assign_role(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            &actor,
            &request.subject,
            &request.role_id,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .map_err(|failure| PluginError::domain(map_assign_role_failure(failure)))?;
        Ok(AssignRoleResponse {
            changed: mutation.changed,
            policy_revision: revision_string(mutation.revision)?,
        })
    }

    async fn revoke_role(
        &self,
        context: Ctx,
        request: RevokeRoleRequest,
    ) -> PluginResult<RevokeRoleResponse, RevokeRoleError> {
        let actor = self
            .authenticated_subject(&context, admin::REVOKE_ROLE_OPERATION)
            .map_err(|()| PluginError::domain(RevokeRoleError::Unauthenticated))?;
        let scope = ScopeKey {
            kind: request.scope.kind,
            id: request.scope.id,
        };
        if !valid_scope(&scope)
            || !valid_subject(&request.subject)
            || !valid_role_id(&request.role_id)
        {
            return Err(PluginError::domain(RevokeRoleError::InvalidRequest));
        }
        let mutation = storage::revoke_role(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &scope,
            &actor,
            &request.subject,
            &request.role_id,
        )
        .await
        .map_err(|error| storage_runtime(&error))?
        .map_err(|failure| PluginError::domain(map_revoke_role_failure(failure)))?;
        Ok(RevokeRoleResponse {
            changed: mutation.changed,
            policy_revision: revision_string(mutation.revision)?,
        })
    }

    fn prepared(&self) -> Result<PreparedAccessControl, RuntimeFailure> {
        self.prepared.borrow().clone().ok_or_else(not_prepared)
    }

    fn bootstrap_authorized(&self, context: &Ctx) -> bool {
        context.caller_instance().is_some_and(|caller| {
            self.config
                .bootstrap_callers
                .iter()
                .any(|allowed| allowed == caller)
        })
    }

    fn directory_authorized(&self, context: &Ctx) -> bool {
        context.caller_instance().is_some_and(|caller| {
            self.config
                .directory_callers
                .iter()
                .any(|allowed| allowed == caller)
        })
    }

    fn authenticated_subject(&self, context: &Ctx, operation: &str) -> Result<String, ()> {
        let actor = self
            .config
            .verifier()
            .map_err(|_| ())?
            .project_context::<AccessControlActor>(
                context,
                admin::CAPABILITY_ID,
                operation,
                &UtcClock,
            )
            .map_err(|_| ())?;
        valid_subject(&actor.subject)
            .then_some(actor.subject)
            .ok_or(())
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

#[derive(Clone, Debug)]
struct AccessControlActor {
    subject: String,
}

impl TypedActor for AccessControlActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct UtcClock;

impl AssertionClock for UtcClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
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

fn create_role_response(mutation: Mutation) -> PluginResult<CreateRoleResponse, CreateRoleError> {
    Ok(CreateRoleResponse {
        changed: mutation.changed,
        policy_revision: revision_string(mutation.revision)?,
    })
}

fn revision_string<E>(revision: i64) -> Result<String, PluginError<E>> {
    if revision < 0 {
        Err(PluginError::runtime(RuntimeFailure::Internal {
            detail: "Access Control revision is negative".to_owned(),
        }))
    } else {
        Ok(revision.to_string())
    }
}

fn storage_runtime<E>(error: &storage::StorageError) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    })
}

fn not_prepared() -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: "Access Control is not prepared".to_owned(),
    }
}

fn map_bootstrap_failure(failure: DomainFailure) -> BootstrapScopeError {
    match failure {
        DomainFailure::Forbidden => BootstrapScopeError::Forbidden,
        DomainFailure::ScopeAlreadyBootstrapped => BootstrapScopeError::ScopeAlreadyBootstrapped,
        _ => BootstrapScopeError::InvalidRequest,
    }
}

fn map_create_role_failure(failure: DomainFailure) -> CreateRoleError {
    match failure {
        DomainFailure::Forbidden => CreateRoleError::Forbidden,
        DomainFailure::ScopeNotBootstrapped => CreateRoleError::ScopeNotBootstrapped,
        DomainFailure::RoleAlreadyExists => CreateRoleError::RoleAlreadyExists,
        DomainFailure::RoleNotFound => CreateRoleError::RoleNotFound,
        DomainFailure::ProtectedRole => CreateRoleError::ProtectedRole,
        DomainFailure::ProtectedBinding => CreateRoleError::ProtectedBinding,
        DomainFailure::ScopeAlreadyBootstrapped => CreateRoleError::InvalidRequest,
    }
}

fn map_set_permissions_failure(failure: DomainFailure) -> SetRolePermissionsError {
    match failure {
        DomainFailure::Forbidden => SetRolePermissionsError::Forbidden,
        DomainFailure::ScopeNotBootstrapped => SetRolePermissionsError::ScopeNotBootstrapped,
        DomainFailure::RoleNotFound => SetRolePermissionsError::RoleNotFound,
        DomainFailure::ProtectedRole => SetRolePermissionsError::ProtectedRole,
        DomainFailure::ProtectedBinding => SetRolePermissionsError::ProtectedBinding,
        DomainFailure::RoleAlreadyExists | DomainFailure::ScopeAlreadyBootstrapped => {
            SetRolePermissionsError::InvalidRequest
        }
    }
}

fn map_delete_role_failure(failure: DomainFailure) -> DeleteRoleError {
    match failure {
        DomainFailure::Forbidden => DeleteRoleError::Forbidden,
        DomainFailure::ScopeNotBootstrapped => DeleteRoleError::ScopeNotBootstrapped,
        DomainFailure::RoleNotFound => DeleteRoleError::RoleNotFound,
        DomainFailure::ProtectedRole => DeleteRoleError::ProtectedRole,
        DomainFailure::ProtectedBinding => DeleteRoleError::ProtectedBinding,
        DomainFailure::RoleAlreadyExists | DomainFailure::ScopeAlreadyBootstrapped => {
            DeleteRoleError::InvalidRequest
        }
    }
}

fn map_assign_role_failure(failure: DomainFailure) -> AssignRoleError {
    match failure {
        DomainFailure::Forbidden => AssignRoleError::Forbidden,
        DomainFailure::ScopeNotBootstrapped => AssignRoleError::ScopeNotBootstrapped,
        DomainFailure::RoleNotFound => AssignRoleError::RoleNotFound,
        DomainFailure::ProtectedRole => AssignRoleError::ProtectedRole,
        DomainFailure::ProtectedBinding => AssignRoleError::ProtectedBinding,
        DomainFailure::RoleAlreadyExists | DomainFailure::ScopeAlreadyBootstrapped => {
            AssignRoleError::InvalidRequest
        }
    }
}

fn map_revoke_role_failure(failure: DomainFailure) -> RevokeRoleError {
    match failure {
        DomainFailure::Forbidden => RevokeRoleError::Forbidden,
        DomainFailure::ScopeNotBootstrapped => RevokeRoleError::ScopeNotBootstrapped,
        DomainFailure::RoleNotFound => RevokeRoleError::RoleNotFound,
        DomainFailure::ProtectedRole => RevokeRoleError::ProtectedRole,
        DomainFailure::ProtectedBinding => RevokeRoleError::ProtectedBinding,
        DomainFailure::RoleAlreadyExists | DomainFailure::ScopeAlreadyBootstrapped => {
            RevokeRoleError::InvalidRequest
        }
    }
}

fn map_get_role_failure(failure: DomainFailure) -> GetRoleError {
    match failure {
        DomainFailure::ScopeNotBootstrapped => GetRoleError::ScopeNotBootstrapped,
        DomainFailure::RoleNotFound => GetRoleError::RoleNotFound,
        _ => GetRoleError::InvalidRequest,
    }
}

fn map_list_roles_failure(failure: DomainFailure) -> ListRolesError {
    match failure {
        DomainFailure::ScopeNotBootstrapped => ListRolesError::ScopeNotBootstrapped,
        _ => ListRolesError::InvalidRequest,
    }
}

fn map_list_subject_roles_failure(failure: DomainFailure) -> ListSubjectRolesError {
    match failure {
        DomainFailure::ScopeNotBootstrapped => ListSubjectRolesError::ScopeNotBootstrapped,
        _ => ListSubjectRolesError::InvalidRequest,
    }
}

fn directory_role(role: storage::DirectoryRole) -> Role {
    Role {
        name: role.name,
        permissions: role.permissions,
        protected: role.protected,
        role_id: role.role_id,
    }
}

fn valid_directory_page(limit: i64, cursor: Option<&str>) -> Option<usize> {
    if !(1..=100).contains(&limit) || cursor.is_some_and(|value| !valid_role_id(value)) {
        return None;
    }
    usize::try_from(limit).ok()
}

fn valid_scope(scope: &ScopeKey) -> bool {
    valid_scope_kind(&scope.kind) && valid_opaque_id(&scope.id, MAX_SCOPE_ID_BYTES)
}

fn valid_scope_kind(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_KIND_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_subject(value: &str) -> bool {
    valid_opaque_id(value, MAX_SUBJECT_BYTES)
}

fn valid_role_id(value: &str) -> bool {
    valid_opaque_id(value, MAX_ROLE_ID_BYTES)
}

fn valid_permission(value: &str) -> bool {
    valid_opaque_id(value, MAX_PERMISSION_BYTES) && value.contains('.')
}

fn valid_opaque_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn valid_display_name(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && value.len() <= MAX_ROLE_NAME_BYTES && !value.chars().any(char::is_control)
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    valid_opaque_id(value, maximum) && !value.contains('/')
}

fn valid_secret_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 256
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && valid_opaque_id(reference, 256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_app_plan::{AppComposition, PluginInstancePlan};
    use lenso_auth_sdk::{ActorAssertionIssuer, Validity, audience};
    use lenso_kernel::{CancellationToken, InvocationContext};
    use lenso_native_adapter::NativePluginRegistry;
    use time::Duration as TimeDuration;

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
    fn identifiers_are_stable_and_narrow() {
        assert!(valid_scope(&ScopeKey {
            kind: "organization".to_owned(),
            id: "org_42".to_owned(),
        }));
        assert!(!valid_scope_kind("Organization"));
        assert!(valid_permission("support.ticket.read"));
        assert!(!valid_permission("read"));
        assert!(!valid_role_id("role with spaces"));
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
    fn actor_assertions_are_bound_to_the_exact_admin_operation() {
        let issuer = ActorAssertionIssuer::new("auth.users", b"access-control-test-key");
        let now = OffsetDateTime::now_utc();
        let assertion = issuer.issue(
            "usr_admin",
            "user",
            "strong",
            [audience(admin::CAPABILITY_ID, admin::CREATE_ROLE_OPERATION)],
            Validity::new(
                now - TimeDuration::seconds(1),
                now + TimeDuration::minutes(1),
            )
            .unwrap(),
            std::collections::BTreeMap::default(),
        );
        let context = assertion.attach(context("organization-api")).unwrap();

        assert_eq!(
            plugin().authenticated_subject(&context, admin::CREATE_ROLE_OPERATION),
            Ok("usr_admin".to_owned())
        );
        assert_eq!(
            plugin().authenticated_subject(&context, admin::DELETE_ROLE_OPERATION),
            Err(())
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
