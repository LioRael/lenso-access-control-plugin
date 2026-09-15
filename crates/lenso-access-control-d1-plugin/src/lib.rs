//! D1 Access Control Plugin. The Host supplies an event-owned primary binding.
pub mod schema;
pub mod storage;
#[cfg(test)]
mod tests;
#[cfg(target_arch = "wasm32")]
pub mod workers;
use futures::future::LocalBoxFuture;
use lenso::prelude::*;
use lenso_access_control_core::{AccessControl, PolicyConfig};
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
use lenso_kernel::RuntimeFailure;
use lenso_migration_d1::{Error, Statement, Transport};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D1Config {
    binding: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    bootstrap_callers: Vec<String>,
    #[serde(default)]
    directory_callers: Vec<String>,
}
impl D1Config {
    fn policy(&self) -> PolicyConfig {
        PolicyConfig {
            auth_issuer: self.auth_issuer.clone(),
            auth_assertion_public_key: self.auth_assertion_public_key.clone(),
            bootstrap_callers: self.bootstrap_callers.clone(),
            directory_callers: self.directory_callers.clone(),
        }
    }
}
fn validate_config(config: &D1Config) -> Result<(), RuntimeFailure> {
    if config.binding.is_empty()
        || config.binding.len() > 128
        || !config.binding.as_bytes()[0].is_ascii_alphabetic()
        || !config
            .binding
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: "invalid Access Control D1 binding name".into(),
        });
    }
    config
        .policy()
        .validate()
        .map_err(|e| RuntimeFailure::InvalidResolvedPlan {
            detail: e.to_string(),
        })
}
/// Explicit primary D1 transport. Requests must stop when the owning event closes.
pub trait Binding: Transport + std::fmt::Debug {}
impl<T: Transport + std::fmt::Debug> Binding for T {}
#[derive(Clone, Debug, Default)]
struct EventBinding(Option<Rc<dyn Binding>>);
impl Transport for EventBinding {
    fn batch(
        &self,
        statements: Vec<Statement>,
    ) -> LocalBoxFuture<'_, Result<Vec<Vec<Value>>, Error>> {
        Box::pin(async move {
            self.0
                .as_ref()
                .ok_or(Error::Transport)?
                .batch(statements)
                .await
        })
    }
}
#[lenso::plugin(lifecycle,configuration_schema="config.schema.json",validate=validate_config)]
#[derive(Clone, Debug)]
struct D1AccessControlPlugin {
    #[config]
    config: D1Config,
    binding: EventBinding,
    prepared: Rc<RefCell<bool>>,
}
#[lenso::provides(
    access_control::AccessControl,
    admin::AccessControlAdmin,
    directory::AccessControlDirectory
)]
impl D1AccessControlPlugin {}
impl D1AccessControlPlugin {
    fn service(&self) -> AccessControl<storage::D1Store<EventBinding>> {
        let binding = if *self.prepared.borrow() {
            self.binding.clone()
        } else {
            EventBinding::default()
        };
        AccessControl::new(self.config.policy(), storage::D1Store(binding))
    }
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
}
impl Lifecycle for D1AccessControlPlugin {
    async fn activate(&self, _context: ActivateContext) -> Result<(), RuntimeFailure> {
        schema::plan()
            .map_err(|error| migration_failure(&error))?
            .verify(&self.binding)
            .await
            .map_err(|error| migration_failure(&error))?;
        *self.prepared.borrow_mut() = true;
        Ok(())
    }
    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        *self.prepared.borrow_mut() = false;
        Ok(())
    }
}
fn migration_failure(error: &Error) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    }
}
/// The Host creates one factory per event and must match the configured binding exactly.
pub fn factory(
    name: impl Into<String>,
    binding: Rc<dyn Binding>,
) -> impl lenso_native_adapter::NativePluginFactory {
    let name = name.into();
    lenso_native_adapter::ConfiguredPluginFactory::<D1AccessControlPlugin, _>::new(move |value| {
        if value.config.binding != name {
            return Err(RuntimeFailure::InvalidResolvedPlan {
                detail: "Access Control factory requires its exact configured D1 binding".into(),
            });
        }
        value.binding = EventBinding(Some(binding.clone()));
        Ok(())
    })
}
