//! Domain storage operations. Implementations must authorize and mutate atomically.
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeKey {
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub allowed: bool,
    pub revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mutation {
    pub changed: bool,
    pub revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bootstrap {
    pub created: bool,
    pub revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryRole {
    pub role_id: String,
    pub name: String,
    pub protected: bool,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryRolePage {
    pub roles: Vec<DirectoryRole>,
    pub revision: i64,
    pub has_more: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainFailure {
    Forbidden,
    ScopeAlreadyBootstrapped,
    ScopeNotBootstrapped,
    RoleAlreadyExists,
    RoleNotFound,
    ProtectedRole,
    ProtectedBinding,
}

#[allow(async_fn_in_trait)]
pub trait Store: Clone + std::fmt::Debug {
    type Error: std::fmt::Display;
    async fn check_permission(
        &self,
        scope: &ScopeKey,
        subject: &str,
        permission: &str,
    ) -> Result<Decision, Self::Error>;
    async fn get_role(
        &self,
        scope: &ScopeKey,
        role_id: &str,
    ) -> Result<Result<(DirectoryRole, i64), DomainFailure>, Self::Error>;
    async fn list_roles(
        &self,
        scope: &ScopeKey,
        after_role_id: Option<&str>,
        limit: usize,
    ) -> Result<Result<DirectoryRolePage, DomainFailure>, Self::Error>;
    async fn list_subject_roles(
        &self,
        scope: &ScopeKey,
        subject: &str,
        after_role_id: Option<&str>,
        limit: usize,
    ) -> Result<Result<DirectoryRolePage, DomainFailure>, Self::Error>;
    async fn bootstrap_scope(
        &self,
        scope: &ScopeKey,
        subject: &str,
    ) -> Result<Result<Bootstrap, DomainFailure>, Self::Error>;
    async fn create_role(
        &self,
        scope: &ScopeKey,
        actor: &str,
        role_id: &str,
        name: &str,
    ) -> Result<Result<Mutation, DomainFailure>, Self::Error>;
    async fn set_role_permissions(
        &self,
        scope: &ScopeKey,
        actor: &str,
        role_id: &str,
        permissions: &BTreeSet<String>,
    ) -> Result<Result<Mutation, DomainFailure>, Self::Error>;
    async fn delete_role(
        &self,
        scope: &ScopeKey,
        actor: &str,
        role_id: &str,
    ) -> Result<Result<Mutation, DomainFailure>, Self::Error>;
    async fn assign_role(
        &self,
        scope: &ScopeKey,
        actor: &str,
        subject: &str,
        role_id: &str,
    ) -> Result<Result<Mutation, DomainFailure>, Self::Error>;
    async fn revoke_role(
        &self,
        scope: &ScopeKey,
        actor: &str,
        subject: &str,
        role_id: &str,
    ) -> Result<Result<Mutation, DomainFailure>, Self::Error>;
}
