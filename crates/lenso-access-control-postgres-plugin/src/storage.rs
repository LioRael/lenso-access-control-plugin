use std::collections::BTreeSet;

use lenso_postgres_kit::OwnedPostgres;
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;

use crate::{BINDINGS_MANAGE_PERMISSION, BOOTSTRAP_ROLE_ID, ROLES_MANAGE_PERMISSION};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScopeKey {
    pub(crate) kind: String,
    pub(crate) id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Decision {
    pub(crate) allowed: bool,
    pub(crate) revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Mutation {
    pub(crate) changed: bool,
    pub(crate) revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Bootstrap {
    pub(crate) created: bool,
    pub(crate) revision: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainFailure {
    Forbidden,
    ScopeAlreadyBootstrapped,
    ScopeNotBootstrapped,
    RoleAlreadyExists,
    RoleNotFound,
    ProtectedRole,
    ProtectedBinding,
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("stored Access Control revision is negative")]
    InvalidRevision,
    #[error("protected bootstrap policy is incomplete")]
    InvalidBootstrapPolicy,
}

pub(crate) async fn check_permission(
    postgres: &OwnedPostgres,
    scope: &ScopeKey,
    subject: &str,
    permission: &str,
) -> Result<Decision, StorageError> {
    let row = sqlx::query(
        "SELECT s.policy_revision, EXISTS(SELECT 1 FROM access_control_subject_roles b JOIN access_control_role_permissions p ON p.scope_kind=b.scope_kind AND p.scope_id=b.scope_id AND p.role_id=b.role_id WHERE b.scope_kind=s.scope_kind AND b.scope_id=s.scope_id AND b.subject=$3 AND p.permission=$4) AS allowed FROM access_control_scopes s WHERE s.scope_kind=$1 AND s.scope_id=$2",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(subject)
    .bind(permission)
    .fetch_optional(postgres.pool())
    .await
    .map_err(|source| database("check permission", source))?;

    let Some(row) = row else {
        return Ok(Decision {
            allowed: false,
            revision: 0,
        });
    };
    let revision: i64 = row
        .try_get("policy_revision")
        .map_err(|source| database("decode policy revision", source))?;
    if revision < 0 {
        return Err(StorageError::InvalidRevision);
    }
    Ok(Decision {
        allowed: row
            .try_get("allowed")
            .map_err(|source| database("decode permission decision", source))?,
        revision,
    })
}

pub(crate) async fn bootstrap_scope(
    postgres: &OwnedPostgres,
    scope: &ScopeKey,
    subject: &str,
) -> Result<Result<Bootstrap, DomainFailure>, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database("begin bootstrap", source))?;
    let inserted = sqlx::query(
        "INSERT INTO access_control_scopes(scope_kind,scope_id,bootstrap_subject) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING policy_revision",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(subject)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("create scope policy", source))?;

    if inserted.is_none() {
        let row = sqlx::query(
            "SELECT bootstrap_subject, policy_revision FROM access_control_scopes WHERE scope_kind=$1 AND scope_id=$2 FOR UPDATE",
        )
        .bind(&scope.kind)
        .bind(&scope.id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|source| database("read existing bootstrap", source))?;
        let existing_subject: String = row
            .try_get("bootstrap_subject")
            .map_err(|source| database("decode bootstrap subject", source))?;
        let revision = revision(&row)?;
        if existing_subject != subject {
            return Ok(Err(DomainFailure::ScopeAlreadyBootstrapped));
        }
        verify_bootstrap_policy(&mut transaction, scope).await?;
        transaction
            .commit()
            .await
            .map_err(|source| database("commit idempotent bootstrap", source))?;
        return Ok(Ok(Bootstrap {
            created: false,
            revision,
        }));
    }

    sqlx::query(
        "INSERT INTO access_control_roles(scope_kind,scope_id,role_id,name,protected) VALUES($1,$2,$3,'Bootstrap administrator',TRUE)",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(BOOTSTRAP_ROLE_ID)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("create bootstrap role", source))?;
    for permission in [ROLES_MANAGE_PERMISSION, BINDINGS_MANAGE_PERMISSION] {
        sqlx::query(
            "INSERT INTO access_control_role_permissions(scope_kind,scope_id,role_id,permission) VALUES($1,$2,$3,$4)",
        )
        .bind(&scope.kind)
        .bind(&scope.id)
        .bind(BOOTSTRAP_ROLE_ID)
        .bind(permission)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("grant bootstrap permission", source))?;
    }
    sqlx::query(
        "INSERT INTO access_control_subject_roles(scope_kind,scope_id,subject,role_id) VALUES($1,$2,$3,$4)",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(subject)
    .bind(BOOTSTRAP_ROLE_ID)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("bind bootstrap role", source))?;
    let revision = bump_revision(&mut transaction, scope).await?;
    transaction
        .commit()
        .await
        .map_err(|source| database("commit bootstrap", source))?;
    Ok(Ok(Bootstrap {
        created: true,
        revision,
    }))
}

pub(crate) async fn create_role(
    postgres: &OwnedPostgres,
    scope: &ScopeKey,
    actor: &str,
    role_id: &str,
    name: &str,
) -> Result<Result<Mutation, DomainFailure>, StorageError> {
    let mut authorized = begin_authorized(postgres, scope, actor, ROLES_MANAGE_PERMISSION).await?;
    let Some((mut transaction, _current_revision)) = authorized.take() else {
        return Ok(Err(authorized.failure));
    };
    let inserted = sqlx::query(
        "INSERT INTO access_control_roles(scope_kind,scope_id,role_id,name,protected) VALUES($1,$2,$3,$4,FALSE) ON CONFLICT DO NOTHING RETURNING role_id",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(role_id)
    .bind(name)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("create role", source))?;
    if inserted.is_none() {
        return Ok(Err(DomainFailure::RoleAlreadyExists));
    }
    let revision = bump_revision(&mut transaction, scope).await?;
    commit(transaction, "commit role creation").await?;
    Ok(Ok(Mutation {
        changed: true,
        revision,
    }))
}

pub(crate) async fn set_role_permissions(
    postgres: &OwnedPostgres,
    scope: &ScopeKey,
    actor: &str,
    role_id: &str,
    permissions: &BTreeSet<String>,
) -> Result<Result<Mutation, DomainFailure>, StorageError> {
    let mut authorized = begin_authorized(postgres, scope, actor, ROLES_MANAGE_PERMISSION).await?;
    let Some((mut transaction, current_revision)) = authorized.take() else {
        return Ok(Err(authorized.failure));
    };
    match role_protection(&mut transaction, scope, role_id).await? {
        None => return Ok(Err(DomainFailure::RoleNotFound)),
        Some(true) => return Ok(Err(DomainFailure::ProtectedRole)),
        Some(false) => {}
    }
    let rows = sqlx::query(
        "SELECT permission FROM access_control_role_permissions WHERE scope_kind=$1 AND scope_id=$2 AND role_id=$3 ORDER BY permission",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(role_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|source| database("read role permissions", source))?;
    let existing = rows
        .into_iter()
        .map(|row| {
            row.try_get("permission")
                .map_err(|source| database("decode role permission", source))
        })
        .collect::<Result<BTreeSet<String>, _>>()?;
    if &existing == permissions {
        commit(transaction, "commit unchanged role permissions").await?;
        return Ok(Ok(Mutation {
            changed: false,
            revision: current_revision,
        }));
    }
    sqlx::query(
        "DELETE FROM access_control_role_permissions WHERE scope_kind=$1 AND scope_id=$2 AND role_id=$3",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(role_id)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("replace role permissions", source))?;
    for permission in permissions {
        sqlx::query(
            "INSERT INTO access_control_role_permissions(scope_kind,scope_id,role_id,permission) VALUES($1,$2,$3,$4)",
        )
        .bind(&scope.kind)
        .bind(&scope.id)
        .bind(role_id)
        .bind(permission)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("insert role permission", source))?;
    }
    let revision = bump_revision(&mut transaction, scope).await?;
    commit(transaction, "commit role permissions").await?;
    Ok(Ok(Mutation {
        changed: true,
        revision,
    }))
}

pub(crate) async fn delete_role(
    postgres: &OwnedPostgres,
    scope: &ScopeKey,
    actor: &str,
    role_id: &str,
) -> Result<Result<Mutation, DomainFailure>, StorageError> {
    let mut authorized = begin_authorized(postgres, scope, actor, ROLES_MANAGE_PERMISSION).await?;
    let Some((mut transaction, _)) = authorized.take() else {
        return Ok(Err(authorized.failure));
    };
    match role_protection(&mut transaction, scope, role_id).await? {
        None => return Ok(Err(DomainFailure::RoleNotFound)),
        Some(true) => return Ok(Err(DomainFailure::ProtectedRole)),
        Some(false) => {}
    }
    sqlx::query(
        "DELETE FROM access_control_roles WHERE scope_kind=$1 AND scope_id=$2 AND role_id=$3",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(role_id)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("delete role", source))?;
    let revision = bump_revision(&mut transaction, scope).await?;
    commit(transaction, "commit role deletion").await?;
    Ok(Ok(Mutation {
        changed: true,
        revision,
    }))
}

pub(crate) async fn assign_role(
    postgres: &OwnedPostgres,
    scope: &ScopeKey,
    actor: &str,
    subject: &str,
    role_id: &str,
) -> Result<Result<Mutation, DomainFailure>, StorageError> {
    let mut authorized =
        begin_authorized(postgres, scope, actor, BINDINGS_MANAGE_PERMISSION).await?;
    let Some((mut transaction, current_revision)) = authorized.take() else {
        return Ok(Err(authorized.failure));
    };
    if role_protection(&mut transaction, scope, role_id)
        .await?
        .is_none()
    {
        return Ok(Err(DomainFailure::RoleNotFound));
    }
    let changed = sqlx::query(
        "INSERT INTO access_control_subject_roles(scope_kind,scope_id,subject,role_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(subject)
    .bind(role_id)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("assign role", source))?
    .rows_affected()
        == 1;
    let revision = if changed {
        bump_revision(&mut transaction, scope).await?
    } else {
        current_revision
    };
    commit(transaction, "commit role assignment").await?;
    Ok(Ok(Mutation { changed, revision }))
}

pub(crate) async fn revoke_role(
    postgres: &OwnedPostgres,
    scope: &ScopeKey,
    actor: &str,
    subject: &str,
    role_id: &str,
) -> Result<Result<Mutation, DomainFailure>, StorageError> {
    let mut authorized =
        begin_authorized(postgres, scope, actor, BINDINGS_MANAGE_PERMISSION).await?;
    let Some((mut transaction, current_revision)) = authorized.take() else {
        return Ok(Err(authorized.failure));
    };
    let Some(protected) = role_protection(&mut transaction, scope, role_id).await? else {
        return Ok(Err(DomainFailure::RoleNotFound));
    };
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM access_control_subject_roles WHERE scope_kind=$1 AND scope_id=$2 AND subject=$3 AND role_id=$4)",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(subject)
    .bind(role_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("check role binding", source))?;
    if !exists {
        commit(transaction, "commit absent role revocation").await?;
        return Ok(Ok(Mutation {
            changed: false,
            revision: current_revision,
        }));
    }
    if protected {
        let binding_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM access_control_subject_roles WHERE scope_kind=$1 AND scope_id=$2 AND role_id=$3",
        )
        .bind(&scope.kind)
        .bind(&scope.id)
        .bind(role_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|source| database("count protected bindings", source))?;
        if binding_count <= 1 {
            return Ok(Err(DomainFailure::ProtectedBinding));
        }
    }
    sqlx::query(
        "DELETE FROM access_control_subject_roles WHERE scope_kind=$1 AND scope_id=$2 AND subject=$3 AND role_id=$4",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(subject)
    .bind(role_id)
    .execute(&mut *transaction)
    .await
    .map_err(|source| database("revoke role", source))?;
    let revision = bump_revision(&mut transaction, scope).await?;
    commit(transaction, "commit role revocation").await?;
    Ok(Ok(Mutation {
        changed: true,
        revision,
    }))
}

struct AuthorizedTransaction<'a> {
    value: Option<(Transaction<'a, Postgres>, i64)>,
    failure: DomainFailure,
}

impl<'a> AuthorizedTransaction<'a> {
    fn take(&mut self) -> Option<(Transaction<'a, Postgres>, i64)> {
        self.value.take()
    }
}

async fn begin_authorized<'a>(
    postgres: &'a OwnedPostgres,
    scope: &ScopeKey,
    subject: &str,
    permission: &str,
) -> Result<AuthorizedTransaction<'a>, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database("begin administration", source))?;
    let row = sqlx::query(
        "SELECT policy_revision FROM access_control_scopes WHERE scope_kind=$1 AND scope_id=$2 FOR UPDATE",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("lock scope policy", source))?;
    let Some(row) = row else {
        return Ok(AuthorizedTransaction {
            value: None,
            failure: DomainFailure::ScopeNotBootstrapped,
        });
    };
    let revision = revision(&row)?;
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM access_control_subject_roles b JOIN access_control_role_permissions p ON p.scope_kind=b.scope_kind AND p.scope_id=b.scope_id AND p.role_id=b.role_id WHERE b.scope_kind=$1 AND b.scope_id=$2 AND b.subject=$3 AND p.permission=$4)",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(subject)
    .bind(permission)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("authorize administrator", source))?;
    if !allowed {
        return Ok(AuthorizedTransaction {
            value: None,
            failure: DomainFailure::Forbidden,
        });
    }
    Ok(AuthorizedTransaction {
        value: Some((transaction, revision)),
        failure: DomainFailure::Forbidden,
    })
}

async fn role_protection(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ScopeKey,
    role_id: &str,
) -> Result<Option<bool>, StorageError> {
    sqlx::query_scalar(
        "SELECT protected FROM access_control_roles WHERE scope_kind=$1 AND scope_id=$2 AND role_id=$3",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(role_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|source| database("read role protection", source))
}

async fn bump_revision(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ScopeKey,
) -> Result<i64, StorageError> {
    let row = sqlx::query(
        "UPDATE access_control_scopes SET policy_revision=policy_revision+1,updated_at=transaction_timestamp() WHERE scope_kind=$1 AND scope_id=$2 RETURNING policy_revision",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|source| database("advance policy revision", source))?;
    revision(&row)
}

async fn verify_bootstrap_policy(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &ScopeKey,
) -> Result<(), StorageError> {
    let complete: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM access_control_roles r JOIN access_control_subject_roles b ON b.scope_kind=r.scope_kind AND b.scope_id=r.scope_id AND b.role_id=r.role_id WHERE r.scope_kind=$1 AND r.scope_id=$2 AND r.role_id=$3 AND r.protected) AND (SELECT count(*) FROM access_control_role_permissions WHERE scope_kind=$1 AND scope_id=$2 AND role_id=$3 AND permission IN ($4,$5))=2",
    )
    .bind(&scope.kind)
    .bind(&scope.id)
    .bind(BOOTSTRAP_ROLE_ID)
    .bind(ROLES_MANAGE_PERMISSION)
    .bind(BINDINGS_MANAGE_PERMISSION)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|source| database("verify bootstrap policy", source))?;
    if complete {
        Ok(())
    } else {
        Err(StorageError::InvalidBootstrapPolicy)
    }
}

fn revision(row: &sqlx::postgres::PgRow) -> Result<i64, StorageError> {
    let revision = row
        .try_get("policy_revision")
        .map_err(|source| database("decode policy revision", source))?;
    if revision < 0 {
        Err(StorageError::InvalidRevision)
    } else {
        Ok(revision)
    }
}

async fn commit(
    transaction: Transaction<'_, Postgres>,
    operation: &'static str,
) -> Result<(), StorageError> {
    transaction
        .commit()
        .await
        .map_err(|source| database(operation, source))
}

fn database(operation: &'static str, source: sqlx::Error) -> StorageError {
    StorageError::Database { operation, source }
}
