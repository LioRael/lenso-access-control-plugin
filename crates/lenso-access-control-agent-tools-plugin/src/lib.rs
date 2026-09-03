//! Agent-facing Tools over explicitly bound Access Control capabilities.

use lenso::prelude::*;
use lenso_capability_access_control_admin::{
    self as admin, AssignRoleRequest, CreateRoleRequest, DeleteRoleRequest, RevokeRoleRequest,
    SetRolePermissionsRequest,
};
use lenso_capability_access_control_directory::{
    self as directory, GetRoleRequest, ListRolesRequest, ListSubjectRolesRequest,
};
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const GET_ROLE_TOOL: &str = "access_control_get_role";
pub const LIST_ROLES_TOOL: &str = "access_control_list_roles";
pub const LIST_SUBJECT_ROLES_TOOL: &str = "access_control_list_subject_roles";
pub const CREATE_ROLE_TOOL: &str = "access_control_create_role";
pub const SET_ROLE_PERMISSIONS_TOOL: &str = "access_control_set_role_permissions";
pub const DELETE_ROLE_TOOL: &str = "access_control_delete_role";
pub const ASSIGN_ROLE_TOOL: &str = "access_control_assign_role";
pub const REVOKE_ROLE_TOOL: &str = "access_control_revoke_role";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct AccessControlAgentToolsPlugin {
    admin: Port<admin::AccessControlAdminClient>,
    directory: Port<directory::AccessControlDirectoryClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl AccessControlAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tool_contract::CatalogError>>
    {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        macro_rules! invoke {
            ($future:expr, $tool:expr, $domain:path, $runtime:path) => {
                match $future.await {
                    Ok(response) => success($tool, &response),
                    Err($domain(error)) => Err(PluginError::domain(error.as_tool_error())),
                    Err($runtime(error)) => Err(PluginError::runtime(error)),
                }
            };
        }

        match request.name.as_str() {
            GET_ROLE_TOOL => {
                let arguments = decode::<GetRoleRequest>(&request)?;
                invoke!(
                    self.directory.get_role_with_context(context, arguments),
                    GET_ROLE_TOOL,
                    directory::AccessControlDirectoryGetRoleInvocationError::Domain,
                    directory::AccessControlDirectoryGetRoleInvocationError::Runtime
                )
            }
            LIST_ROLES_TOOL => {
                let arguments = decode::<ListRolesRequest>(&request)?;
                invoke!(
                    self.directory.list_roles_with_context(context, arguments),
                    LIST_ROLES_TOOL,
                    directory::AccessControlDirectoryListRolesInvocationError::Domain,
                    directory::AccessControlDirectoryListRolesInvocationError::Runtime
                )
            }
            LIST_SUBJECT_ROLES_TOOL => {
                let arguments = decode::<ListSubjectRolesRequest>(&request)?;
                invoke!(
                    self.directory
                        .list_subject_roles_with_context(context, arguments),
                    LIST_SUBJECT_ROLES_TOOL,
                    directory::AccessControlDirectoryListSubjectRolesInvocationError::Domain,
                    directory::AccessControlDirectoryListSubjectRolesInvocationError::Runtime
                )
            }
            CREATE_ROLE_TOOL => {
                let arguments = decode::<CreateRoleRequest>(&request)?;
                invoke!(
                    self.admin.create_role_with_context(context, arguments),
                    CREATE_ROLE_TOOL,
                    admin::AccessControlAdminCreateRoleInvocationError::Domain,
                    admin::AccessControlAdminCreateRoleInvocationError::Runtime
                )
            }
            SET_ROLE_PERMISSIONS_TOOL => {
                let arguments = decode::<SetRolePermissionsRequest>(&request)?;
                invoke!(
                    self.admin
                        .set_role_permissions_with_context(context, arguments),
                    SET_ROLE_PERMISSIONS_TOOL,
                    admin::AccessControlAdminSetRolePermissionsInvocationError::Domain,
                    admin::AccessControlAdminSetRolePermissionsInvocationError::Runtime
                )
            }
            DELETE_ROLE_TOOL => {
                let arguments = decode::<DeleteRoleRequest>(&request)?;
                invoke!(
                    self.admin.delete_role_with_context(context, arguments),
                    DELETE_ROLE_TOOL,
                    admin::AccessControlAdminDeleteRoleInvocationError::Domain,
                    admin::AccessControlAdminDeleteRoleInvocationError::Runtime
                )
            }
            ASSIGN_ROLE_TOOL => {
                let arguments = decode::<AssignRoleRequest>(&request)?;
                invoke!(
                    self.admin.assign_role_with_context(context, arguments),
                    ASSIGN_ROLE_TOOL,
                    admin::AccessControlAdminAssignRoleInvocationError::Domain,
                    admin::AccessControlAdminAssignRoleInvocationError::Runtime
                )
            }
            REVOKE_ROLE_TOOL => {
                let arguments = decode::<RevokeRoleRequest>(&request)?;
                invoke!(
                    self.admin.revoke_role_with_context(context, arguments),
                    REVOKE_ROLE_TOOL,
                    admin::AccessControlAdminRevokeRoleInvocationError::Domain,
                    admin::AccessControlAdminRevokeRoleInvocationError::Runtime
                )
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            GET_ROLE_TOOL,
            "Get one role, its permissions, protected status, and the current scope policy revision.",
            include_str!(
                "../../lenso-capability-access-control-directory/schemas/get-role-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_ROLES_TOOL,
            "List roles in one exact scope with bounded cursor pagination.",
            include_str!(
                "../../lenso-capability-access-control-directory/schemas/list-roles-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_SUBJECT_ROLES_TOOL,
            "List roles currently assigned to one subject in one exact scope.",
            include_str!(
                "../../lenso-capability-access-control-directory/schemas/list-subject-roles-request.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            CREATE_ROLE_TOOL,
            "Create one role in a bootstrapped scope. Requires an operation-audienced ActorAssertion and scoped role-management permission.",
            include_str!(
                "../../lenso-capability-access-control-admin/schemas/create-role-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            SET_ROLE_PERMISSIONS_TOOL,
            "Replace one role's permission set. Requires an operation-audienced ActorAssertion and scoped role-management permission.",
            include_str!(
                "../../lenso-capability-access-control-admin/schemas/set-role-permissions-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            DELETE_ROLE_TOOL,
            "Delete one unprotected role. Requires an operation-audienced ActorAssertion and scoped role-management permission.",
            include_str!(
                "../../lenso-capability-access-control-admin/schemas/delete-role-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            ASSIGN_ROLE_TOOL,
            "Assign one role to one subject. Requires an operation-audienced ActorAssertion and scoped binding-management permission.",
            include_str!(
                "../../lenso-capability-access-control-admin/schemas/role-binding-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            REVOKE_ROLE_TOOL,
            "Revoke one subject-role binding while preserving the protected bootstrap binding. Requires an operation-audienced ActorAssertion and scoped binding-management permission.",
            include_str!(
                "../../lenso-capability-access-control-admin/schemas/role-binding-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
    ]
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    let schema: serde_json::Value =
        serde_json::from_str(schema).expect("Access Control Tool schema must be valid JSON");
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Access Control Tool schema must remain valid JSON"),
        execution,
    }
}

fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}

fn success<T: Serialize>(
    tool_name: &str,
    response: &T,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(response).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!("Access Control Tool could not serialize its response: {error}"),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": tool_name })
            .to_string()
            .try_into()
            .expect("Access Control Tool metadata must be valid JSON"),
    })
}

trait DomainErrorMapping {
    fn as_tool_error(&self) -> ExecuteError;
}

macro_rules! impl_admin_error_mapping {
    ($error:ty) => {
        impl DomainErrorMapping for $error {
            fn as_tool_error(&self) -> ExecuteError {
                match self {
                    Self::Unauthenticated | Self::Forbidden => ExecuteError::PermissionDenied,
                    Self::InvalidRequest => ExecuteError::InvalidArguments,
                    Self::RoleNotFound => ExecuteError::NotFound,
                    Self::ScopeNotBootstrapped => rejected("scope_not_bootstrapped"),
                    Self::RoleAlreadyExists => rejected("role_already_exists"),
                    Self::ProtectedRole => rejected("protected_role"),
                    Self::ProtectedBinding => rejected("protected_binding"),
                    Self::Unknown(_) => rejected("unknown_domain_error"),
                }
            }
        }
    };
}

impl_admin_error_mapping!(admin::AssignRoleError);
impl_admin_error_mapping!(admin::CreateRoleError);
impl_admin_error_mapping!(admin::DeleteRoleError);
impl_admin_error_mapping!(admin::RevokeRoleError);
impl_admin_error_mapping!(admin::SetRolePermissionsError);

impl DomainErrorMapping for directory::GetRoleError {
    fn as_tool_error(&self) -> ExecuteError {
        match self {
            Self::Forbidden => ExecuteError::PermissionDenied,
            Self::InvalidRequest => ExecuteError::InvalidArguments,
            Self::RoleNotFound => ExecuteError::NotFound,
            Self::ScopeNotBootstrapped => rejected("scope_not_bootstrapped"),
            Self::Unknown(_) => rejected("unknown_domain_error"),
        }
    }
}

macro_rules! impl_list_error_mapping {
    ($error:ty) => {
        impl DomainErrorMapping for $error {
            fn as_tool_error(&self) -> ExecuteError {
                match self {
                    Self::Forbidden => ExecuteError::PermissionDenied,
                    Self::InvalidPage | Self::InvalidRequest => ExecuteError::InvalidArguments,
                    Self::ScopeNotBootstrapped => rejected("scope_not_bootstrapped"),
                    Self::Unknown(_) => rejected("unknown_domain_error"),
                }
            }
        }
    };
}

impl_list_error_mapping!(directory::ListRolesError);
impl_list_error_mapping!(directory::ListSubjectRolesError);

fn rejected(reason_code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: reason_code.to_owned(),
            message: "Access Control rejected the requested operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Access Control Tool error metadata must be valid JSON"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, arguments: &str) -> ExecuteRequest {
        ExecuteRequest {
            name: name.to_owned(),
            arguments_json: arguments.try_into().unwrap(),
        }
    }

    #[test]
    fn descriptor_requires_only_directory_and_admin_roles() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(descriptor["plugin_id"], "lenso.access-control.agent-tools");
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.agent.tool-provider@2"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 2);
        assert!(
            required.iter().any(|requirement| {
                requirement["capability_id"] == "lenso.access-control-admin@1"
            })
        );
        assert!(required.iter().any(|requirement| {
            requirement["capability_id"] == "lenso.access-control-directory@1"
        }));
    }

    #[test]
    fn catalog_separates_reads_from_mutations_and_excludes_bootstrap() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 8);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            3
        );
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::Exclusive)
                .count(),
            5
        );
        assert!(tools.iter().all(|tool| !tool.name.contains("bootstrap")));
    }

    #[test]
    fn requests_and_domain_failures_preserve_contract_semantics() {
        let list = decode::<ListRolesRequest>(&request(
            LIST_ROLES_TOOL,
            r#"{"scope":{"kind":"organization","id":"org_acme"},"limit":50,"cursor":null}"#,
        ))
        .unwrap();
        assert_eq!(list.limit, 50);
        assert!(
            decode::<ListRolesRequest>(&request(
                LIST_ROLES_TOOL,
                r#"{"scope":{"kind":"organization","id":"org_acme"},"limit":"50","cursor":null}"#,
            ))
            .is_err()
        );
        assert_eq!(
            admin::CreateRoleError::Unauthenticated.as_tool_error(),
            ExecuteError::PermissionDenied
        );
        assert_eq!(
            directory::GetRoleError::RoleNotFound.as_tool_error(),
            ExecuteError::NotFound
        );
        assert!(matches!(
            admin::RevokeRoleError::ProtectedBinding.as_tool_error(),
            ExecuteError::ExecutionFailed { .. }
        ));
    }
}
