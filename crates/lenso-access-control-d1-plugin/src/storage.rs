//! All administration decisions and writes share one primary atomic batch.
use lenso_access_control_core::{
    BINDINGS_MANAGE_PERMISSION, BOOTSTRAP_ROLE_ID, ROLES_MANAGE_PERMISSION,
    storage::{
        Bootstrap, Decision, DirectoryRole, DirectoryRolePage, DomainFailure, Mutation, ScopeKey,
        Store,
    },
};
use lenso_migration_d1::{Statement, Transport};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("D1 Access Control operation failed; a submitted write may have committed")]
    Transport,
    #[error("invalid stored Access Control state or receipt")]
    InvalidState,
}

#[derive(Clone, Debug)]
pub struct D1Store<T>(pub T);
const SCOPE: &str = "(scope_kind,scope_id)=(SELECT kind,id FROM access_control_operation)";
const ROLE: &str = "role_id=(SELECT role_id FROM access_control_operation)";
const SUBJECT: &str = "subject=(SELECT subject FROM access_control_operation)";
const APPLY: &str = "(SELECT failure IS NULL AND changed=1 FROM access_control_operation)";

fn stmt(sql: impl Into<String>) -> Statement {
    Statement::new(sql, vec![])
}
fn revision(row: &Value) -> Result<i64, Error> {
    row["revision"]
        .as_str()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|v| *v >= 0)
        .ok_or(Error::InvalidState)
}
fn flag(row: &Value, key: &str) -> Result<bool, Error> {
    match row[key].as_i64() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        _ => Err(Error::InvalidState),
    }
}
fn domain(row: &Value) -> Result<Option<DomainFailure>, Error> {
    Ok(match row["failure"].as_str() {
        None if row.get("failure") == Some(&Value::Null) => None,
        Some("scope_missing") => Some(DomainFailure::ScopeNotBootstrapped),
        Some("scope_exists") => Some(DomainFailure::ScopeAlreadyBootstrapped),
        Some("forbidden") => Some(DomainFailure::Forbidden),
        Some("role_exists") => Some(DomainFailure::RoleAlreadyExists),
        Some("role_missing") => Some(DomainFailure::RoleNotFound),
        Some("protected_role") => Some(DomainFailure::ProtectedRole),
        Some("protected_binding") => Some(DomainFailure::ProtectedBinding),
        _ => return Err(Error::InvalidState),
    })
}

impl<T: Transport + Clone + std::fmt::Debug> D1Store<T> {
    async fn run(&self, statements: Vec<Statement>) -> Result<Vec<Vec<Value>>, Error> {
        let count = statements.len();
        let rows = self
            .0
            .batch(statements)
            .await
            .map_err(|_| Error::Transport)?;
        if rows.len() != count {
            return Err(Error::InvalidState);
        }
        Ok(rows)
    }
    async fn mutation(
        &self,
        operation: &str,
        scope: &ScopeKey,
        input: Value,
    ) -> Result<Result<Mutation, DomainFailure>, Error> {
        let mut batch = vec![
            stmt("DELETE FROM access_control_operation"),
            Statement::new(
                "INSERT INTO access_control_operation(singleton,kind,id,actor,subject,role_id,name,permissions) VALUES(1,?1,?2,json_extract(?3,'$.actor'),json_extract(?3,'$.subject'),json_extract(?3,'$.role'),json_extract(?3,'$.name'),json_extract(?3,'$.permissions'))",
                vec![json!(scope.kind), json!(scope.id), json!(input.to_string())],
            ),
        ];
        let scope_exists = format!("EXISTS(SELECT 1 FROM access_control_scopes WHERE {SCOPE})");
        let role_exists =
            format!("EXISTS(SELECT 1 FROM access_control_roles WHERE {SCOPE} AND {ROLE})");
        let protected = format!(
            "EXISTS(SELECT 1 FROM access_control_roles WHERE {SCOPE} AND {ROLE} AND protected=1)"
        );
        let bound = format!(
            "EXISTS(SELECT 1 FROM access_control_subject_roles WHERE {SCOPE} AND {ROLE} AND {SUBJECT})"
        );
        let (failure, changed) = if operation == "bootstrap" {
            (
                format!(
                    "CASE WHEN {scope_exists} AND (SELECT bootstrap_subject FROM access_control_scopes WHERE {SCOPE}) != subject THEN 'scope_exists' WHEN {scope_exists} AND NOT (EXISTS(SELECT 1 FROM access_control_roles WHERE {SCOPE} AND role_id='{BOOTSTRAP_ROLE_ID}' AND protected=1) AND EXISTS(SELECT 1 FROM access_control_subject_roles WHERE {SCOPE} AND role_id='{BOOTSTRAP_ROLE_ID}') AND (SELECT count(*) FROM access_control_role_permissions WHERE {SCOPE} AND role_id='{BOOTSTRAP_ROLE_ID}' AND permission IN ('{ROLES_MANAGE_PERMISSION}','{BINDINGS_MANAGE_PERMISSION}'))=2) THEN 'invalid_bootstrap' END"
                ),
                format!("NOT {scope_exists}"),
            )
        } else {
            let permission = if matches!(operation, "assign" | "revoke") {
                BINDINGS_MANAGE_PERMISSION
            } else {
                ROLES_MANAGE_PERMISSION
            };
            let auth = format!(
                "EXISTS(SELECT 1 FROM access_control_subject_roles b JOIN access_control_role_permissions p USING(scope_kind,scope_id,role_id) WHERE b.scope_kind=kind AND b.scope_id=id AND b.subject=actor AND p.permission='{permission}')"
            );
            let specific = match operation {
                "create" => format!("WHEN {role_exists} THEN 'role_exists'"),
                "set" | "delete" => format!(
                    "WHEN NOT {role_exists} THEN 'role_missing' WHEN {protected} THEN 'protected_role'"
                ),
                "assign" => format!("WHEN NOT {role_exists} THEN 'role_missing'"),
                "revoke" => format!(
                    "WHEN NOT {role_exists} THEN 'role_missing' WHEN {protected} AND {bound} AND (SELECT count(*) FROM access_control_subject_roles WHERE {SCOPE} AND {ROLE})<=1 THEN 'protected_binding'"
                ),
                _ => return Err(Error::InvalidState),
            };
            let changed = match operation {
                "assign" => format!("NOT {bound}"),
                "revoke" => bound,
                "set" => format!(
                    "EXISTS(SELECT permission FROM access_control_role_permissions WHERE {SCOPE} AND {ROLE} EXCEPT SELECT value FROM json_each(permissions)) OR EXISTS(SELECT value FROM json_each(permissions) EXCEPT SELECT permission FROM access_control_role_permissions WHERE {SCOPE} AND {ROLE})"
                ),
                _ => "1".to_owned(),
            };
            (
                format!(
                    "CASE WHEN NOT {scope_exists} THEN 'scope_missing' WHEN NOT {auth} THEN 'forbidden' {specific} END"
                ),
                changed,
            )
        };
        batch.push(stmt(format!("UPDATE access_control_operation SET failure={failure},changed=({changed}),revision=COALESCE((SELECT policy_revision FROM access_control_scopes WHERE {SCOPE}),0)")));
        match operation {
            "bootstrap"=> {
                batch.push(stmt(format!("INSERT INTO access_control_scopes(scope_kind,scope_id,bootstrap_subject) SELECT kind,id,subject FROM access_control_operation WHERE {APPLY}")));
                batch.push(stmt(format!("INSERT INTO access_control_roles(scope_kind,scope_id,role_id,name,protected) SELECT kind,id,'{BOOTSTRAP_ROLE_ID}','Bootstrap administrator',1 FROM access_control_operation WHERE {APPLY}")));
                for permission in [ROLES_MANAGE_PERMISSION,BINDINGS_MANAGE_PERMISSION] {
                    batch.push(stmt(format!("INSERT INTO access_control_role_permissions SELECT kind,id,'{BOOTSTRAP_ROLE_ID}','{permission}' FROM access_control_operation WHERE {APPLY}")));
                }
                batch.push(stmt(format!("INSERT INTO access_control_subject_roles(scope_kind,scope_id,subject,role_id) SELECT kind,id,subject,'{BOOTSTRAP_ROLE_ID}' FROM access_control_operation WHERE {APPLY}")));
            }
            "create"=>batch.push(stmt(format!("INSERT INTO access_control_roles(scope_kind,scope_id,role_id,name,protected) SELECT kind,id,role_id,name,0 FROM access_control_operation WHERE {APPLY}"))),
            "set"=> {
                batch.push(stmt(format!("DELETE FROM access_control_role_permissions WHERE {SCOPE} AND {ROLE} AND {APPLY}")));
                batch.push(stmt(format!("INSERT INTO access_control_role_permissions SELECT o.kind,o.id,o.role_id,value FROM access_control_operation o,json_each(o.permissions) WHERE {APPLY}")));
            }
            "delete"=>batch.push(stmt(format!("DELETE FROM access_control_roles WHERE {SCOPE} AND {ROLE} AND {APPLY}"))),
            "assign"=>batch.push(stmt(format!("INSERT INTO access_control_subject_roles(scope_kind,scope_id,subject,role_id) SELECT kind,id,subject,role_id FROM access_control_operation WHERE {APPLY}"))),
            "revoke"=>batch.push(stmt(format!("DELETE FROM access_control_subject_roles WHERE {SCOPE} AND {ROLE} AND {SUBJECT} AND {APPLY}"))),
            _=>unreachable!(),
        }
        batch.push(stmt(format!("UPDATE access_control_scopes SET policy_revision=policy_revision+1,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE {SCOPE} AND {APPLY}")));
        batch.push(stmt("SELECT failure,changed,CAST(revision + CASE WHEN failure IS NULL THEN changed ELSE 0 END AS TEXT) AS revision FROM access_control_operation"));
        batch.push(stmt("DELETE FROM access_control_operation"));
        let rows = self.run(batch).await?;
        let row = rows
            .get(rows.len() - 2)
            .filter(|r| r.len() == 1)
            .and_then(|r| r.first())
            .ok_or(Error::InvalidState)?;
        if let Some(failure) = domain(row)? {
            return Ok(Err(failure));
        }
        Ok(Ok(Mutation {
            changed: flag(row, "changed")?,
            revision: revision(row)?,
        }))
    }
    async fn directory(
        &self,
        scope: &ScopeKey,
        role: Option<&str>,
        subject: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Result<DirectoryRolePage, DomainFailure>, Error> {
        // Revision and complete sorted permission snapshots come from one SQL statement.
        // One result row per role avoids packing an entire large page into one D1 cell.
        let sql = "SELECT CAST(s.policy_revision AS TEXT) AS revision,r.role_id,r.name,r.protected,(SELECT json_group_array(permission) FROM (SELECT permission FROM access_control_role_permissions p WHERE p.scope_kind=r.scope_kind AND p.scope_id=r.scope_id AND p.role_id=r.role_id ORDER BY permission)) AS permissions FROM access_control_scopes s LEFT JOIN (SELECT * FROM access_control_roles r WHERE r.scope_kind=?1 AND r.scope_id=?2 AND (?3 IS NULL OR r.role_id=?3) AND (?4 IS NULL OR EXISTS(SELECT 1 FROM access_control_subject_roles b WHERE b.scope_kind=r.scope_kind AND b.scope_id=r.scope_id AND b.role_id=r.role_id AND b.subject=?4)) AND (?5 IS NULL OR r.role_id>?5) ORDER BY r.role_id LIMIT ?6) r ON r.scope_kind=s.scope_kind AND r.scope_id=s.scope_id WHERE s.scope_kind=?1 AND s.scope_id=?2 ORDER BY r.role_id";
        let rows = self
            .run(vec![Statement::new(
                sql,
                vec![
                    json!(scope.kind),
                    json!(scope.id),
                    json!(role),
                    json!(subject),
                    json!(cursor),
                    json!(limit + 1),
                ],
            )])
            .await?;
        let Some(row) = rows[0].first() else {
            return Ok(Err(DomainFailure::ScopeNotBootstrapped));
        };
        let values = rows[0]
            .iter()
            .filter(|row| !row["role_id"].is_null())
            .collect::<Vec<_>>();
        let has_more = values.len() > limit;
        let roles = values
            .iter()
            .take(limit)
            .map(|v| {
                Ok(DirectoryRole {
                    role_id: v["role_id"].as_str().ok_or(Error::InvalidState)?.to_owned(),
                    name: v["name"].as_str().ok_or(Error::InvalidState)?.to_owned(),
                    protected: flag(v, "protected")?,
                    permissions: serde_json::from_str(
                        v["permissions"].as_str().ok_or(Error::InvalidState)?,
                    )
                    .map_err(|_| Error::InvalidState)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Ok(DirectoryRolePage {
            roles,
            revision: revision(row)?,
            has_more,
        }))
    }
}
impl<T: Transport + Clone + std::fmt::Debug> Store for D1Store<T> {
    type Error = Error;
    async fn check_permission(
        &self,
        scope: &ScopeKey,
        subject: &str,
        permission: &str,
    ) -> Result<Decision, Error> {
        let rows=self.run(vec![Statement::new("SELECT CAST(s.policy_revision AS TEXT) AS revision, EXISTS(SELECT 1 FROM access_control_subject_roles b JOIN access_control_role_permissions p USING(scope_kind,scope_id,role_id) WHERE b.scope_kind=s.scope_kind AND b.scope_id=s.scope_id AND b.subject=?3 AND p.permission=?4) AS allowed FROM access_control_scopes s WHERE s.scope_kind=?1 AND s.scope_id=?2",vec![json!(scope.kind),json!(scope.id),json!(subject),json!(permission)])]).await?;
        rows[0].first().map_or(
            Ok(Decision {
                allowed: false,
                revision: 0,
            }),
            |row| {
                Ok(Decision {
                    allowed: flag(row, "allowed")?,
                    revision: revision(row)?,
                })
            },
        )
    }
    async fn get_role(
        &self,
        scope: &ScopeKey,
        role_id: &str,
    ) -> Result<Result<(DirectoryRole, i64), DomainFailure>, Error> {
        Ok(
            match self.directory(scope, Some(role_id), None, None, 1).await? {
                Err(e) => Err(e),
                Ok(p) => p
                    .roles
                    .into_iter()
                    .next()
                    .map(|r| (r, p.revision))
                    .ok_or(DomainFailure::RoleNotFound),
            },
        )
    }
    async fn list_roles(
        &self,
        scope: &ScopeKey,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Result<DirectoryRolePage, DomainFailure>, Error> {
        self.directory(scope, None, None, cursor, limit).await
    }
    async fn list_subject_roles(
        &self,
        scope: &ScopeKey,
        subject: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Result<DirectoryRolePage, DomainFailure>, Error> {
        self.directory(scope, None, Some(subject), cursor, limit)
            .await
    }
    async fn bootstrap_scope(
        &self,
        scope: &ScopeKey,
        subject: &str,
    ) -> Result<Result<Bootstrap, DomainFailure>, Error> {
        Ok(self
            .mutation("bootstrap", scope, json!({"subject":subject}))
            .await?
            .map(|m| Bootstrap {
                created: m.changed,
                revision: m.revision,
            }))
    }
    async fn create_role(
        &self,
        scope: &ScopeKey,
        actor: &str,
        role_id: &str,
        name: &str,
    ) -> Result<Result<Mutation, DomainFailure>, Error> {
        self.mutation(
            "create",
            scope,
            json!({"actor":actor,"role":role_id,"name":name}),
        )
        .await
    }
    async fn set_role_permissions(
        &self,
        scope: &ScopeKey,
        actor: &str,
        role_id: &str,
        permissions: &BTreeSet<String>,
    ) -> Result<Result<Mutation, DomainFailure>, Error> {
        self.mutation(
            "set",
            scope,
            json!({"actor":actor,"role":role_id,"permissions":permissions}),
        )
        .await
    }
    async fn delete_role(
        &self,
        scope: &ScopeKey,
        actor: &str,
        role_id: &str,
    ) -> Result<Result<Mutation, DomainFailure>, Error> {
        self.mutation("delete", scope, json!({"actor":actor,"role":role_id}))
            .await
    }
    async fn assign_role(
        &self,
        scope: &ScopeKey,
        actor: &str,
        subject: &str,
        role_id: &str,
    ) -> Result<Result<Mutation, DomainFailure>, Error> {
        self.mutation(
            "assign",
            scope,
            json!({"actor":actor,"subject":subject,"role":role_id}),
        )
        .await
    }
    async fn revoke_role(
        &self,
        scope: &ScopeKey,
        actor: &str,
        subject: &str,
        role_id: &str,
    ) -> Result<Result<Mutation, DomainFailure>, Error> {
        self.mutation(
            "revoke",
            scope,
            json!({"actor":actor,"subject":subject,"role":role_id}),
        )
        .await
    }
}
