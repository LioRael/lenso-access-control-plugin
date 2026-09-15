//! Shared backend qualification vectors, enabled only by test consumers.
use crate::{
    BINDINGS_MANAGE_PERMISSION, BOOTSTRAP_ROLE_ID, ROLES_MANAGE_PERMISSION,
    storage::{Bootstrap, Decision, DirectoryRole, DomainFailure, Mutation, ScopeKey, Store},
};
use std::collections::BTreeSet;

/// Run the same state transitions against a fresh scope on either backend.
#[allow(clippy::too_many_lines)]
pub async fn exercise<S: Store>(store: &S, id: &str)
where
    S::Error: std::fmt::Debug,
{
    let scope = ScopeKey {
        kind: "organization".into(),
        id: id.into(),
    };
    assert_eq!(
        store
            .check_permission(&scope, "owner", "document.read")
            .await
            .unwrap(),
        Decision {
            allowed: false,
            revision: 0
        }
    );
    assert_eq!(
        store
            .create_role(&scope, "owner", "viewer", "Viewer")
            .await
            .unwrap(),
        Err(DomainFailure::ScopeNotBootstrapped)
    );
    assert_eq!(
        store.list_roles(&scope, None, 10).await.unwrap(),
        Err(DomainFailure::ScopeNotBootstrapped)
    );
    assert_eq!(
        store
            .bootstrap_scope(&scope, "owner")
            .await
            .unwrap()
            .unwrap(),
        Bootstrap {
            created: true,
            revision: 1
        }
    );
    assert_eq!(
        store
            .bootstrap_scope(&scope, "owner")
            .await
            .unwrap()
            .unwrap(),
        Bootstrap {
            created: false,
            revision: 1
        }
    );
    assert_eq!(
        store.bootstrap_scope(&scope, "other").await.unwrap(),
        Err(DomainFailure::ScopeAlreadyBootstrapped)
    );
    assert_eq!(
        store
            .create_role(&scope, "stranger", "viewer", "Viewer")
            .await
            .unwrap(),
        Err(DomainFailure::Forbidden)
    );
    assert_eq!(
        store
            .create_role(&scope, "owner", "viewer", "Viewer")
            .await
            .unwrap()
            .unwrap(),
        Mutation {
            changed: true,
            revision: 2
        }
    );
    assert_eq!(
        store
            .create_role(&scope, "owner", "viewer", "Viewer")
            .await
            .unwrap(),
        Err(DomainFailure::RoleAlreadyExists)
    );
    let permissions = BTreeSet::from(["document.read".to_owned(), "document.export".to_owned()]);
    assert_eq!(
        store
            .set_role_permissions(&scope, "owner", "viewer", &permissions)
            .await
            .unwrap()
            .unwrap(),
        Mutation {
            changed: true,
            revision: 3
        }
    );
    assert_eq!(
        store
            .set_role_permissions(&scope, "owner", "viewer", &permissions)
            .await
            .unwrap()
            .unwrap(),
        Mutation {
            changed: false,
            revision: 3
        }
    );
    assert_eq!(
        store
            .assign_role(&scope, "owner", "member", "viewer")
            .await
            .unwrap()
            .unwrap(),
        Mutation {
            changed: true,
            revision: 4
        }
    );
    assert_eq!(
        store
            .assign_role(&scope, "owner", "member", "viewer")
            .await
            .unwrap()
            .unwrap(),
        Mutation {
            changed: false,
            revision: 4
        }
    );
    assert_eq!(
        store
            .check_permission(&scope, "member", "document.read")
            .await
            .unwrap(),
        Decision {
            allowed: true,
            revision: 4
        }
    );
    assert!(
        !store
            .check_permission(&scope, "member", ROLES_MANAGE_PERMISSION)
            .await
            .unwrap()
            .allowed
    );
    assert_eq!(
        store.get_role(&scope, "viewer").await.unwrap().unwrap(),
        (
            DirectoryRole {
                role_id: "viewer".into(),
                name: "Viewer".into(),
                protected: false,
                permissions: permissions.iter().cloned().collect()
            },
            4
        )
    );
    let first = store.list_roles(&scope, None, 1).await.unwrap().unwrap();
    assert_eq!(first.roles[0].role_id, BOOTSTRAP_ROLE_ID);
    assert!(first.has_more);
    assert_eq!(first.revision, 4);
    let next = store
        .list_roles(&scope, Some(BOOTSTRAP_ROLE_ID), 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.roles[0].role_id, "viewer");
    assert!(!next.has_more);
    assert_eq!(next.revision, 4);
    assert_eq!(
        store
            .list_subject_roles(&scope, "member", None, 10)
            .await
            .unwrap()
            .unwrap()
            .roles,
        next.roles
    );
    assert_eq!(
        store
            .revoke_role(&scope, "owner", "nobody", "viewer")
            .await
            .unwrap()
            .unwrap(),
        Mutation {
            changed: false,
            revision: 4
        }
    );
    assert_eq!(
        store
            .delete_role(&scope, "owner", BOOTSTRAP_ROLE_ID)
            .await
            .unwrap(),
        Err(DomainFailure::ProtectedRole)
    );
    assert_eq!(
        store
            .set_role_permissions(&scope, "owner", BOOTSTRAP_ROLE_ID, &permissions)
            .await
            .unwrap(),
        Err(DomainFailure::ProtectedRole)
    );
    assert_eq!(
        store
            .revoke_role(&scope, "owner", "owner", BOOTSTRAP_ROLE_ID)
            .await
            .unwrap(),
        Err(DomainFailure::ProtectedBinding)
    );
    for result in [
        store.assign_role(&scope, "owner", "member", "absent").await,
        store.revoke_role(&scope, "owner", "member", "absent").await,
        store.delete_role(&scope, "owner", "absent").await,
        store
            .set_role_permissions(&scope, "owner", "absent", &permissions)
            .await,
    ] {
        assert_eq!(result.unwrap(), Err(DomainFailure::RoleNotFound));
    }
    assert_eq!(
        store
            .assign_role(&scope, "owner", "other", BOOTSTRAP_ROLE_ID)
            .await
            .unwrap()
            .unwrap()
            .revision,
        5
    );
    assert_eq!(
        store
            .revoke_role(&scope, "other", "owner", BOOTSTRAP_ROLE_ID)
            .await
            .unwrap()
            .unwrap()
            .revision,
        6
    );
    assert_eq!(
        store
            .create_role(&scope, "owner", "denied", "Denied")
            .await
            .unwrap(),
        Err(DomainFailure::Forbidden)
    );
    assert_eq!(
        store
            .revoke_role(&scope, "other", "other", BOOTSTRAP_ROLE_ID)
            .await
            .unwrap(),
        Err(DomainFailure::ProtectedBinding)
    );
    // A maximum-size grant replacement stays one mutation and one revision.
    let maximum = (0..256)
        .map(|i| format!("document.permission{i:03}"))
        .collect();
    assert_eq!(
        store
            .set_role_permissions(&scope, "other", "viewer", &maximum)
            .await
            .unwrap()
            .unwrap()
            .revision,
        7
    );
    assert_eq!(
        store
            .get_role(&scope, "viewer")
            .await
            .unwrap()
            .unwrap()
            .0
            .permissions
            .len(),
        256
    );
    assert_eq!(
        store
            .set_role_permissions(&scope, "other", "viewer", &BTreeSet::new())
            .await
            .unwrap()
            .unwrap()
            .revision,
        8
    );
    assert!(
        !store
            .check_permission(&scope, "member", "document.read")
            .await
            .unwrap()
            .allowed
    );
    assert_eq!(
        store
            .delete_role(&scope, "other", "viewer")
            .await
            .unwrap()
            .unwrap()
            .revision,
        9
    );
    assert!(
        store
            .list_subject_roles(&scope, "member", None, 10)
            .await
            .unwrap()
            .unwrap()
            .roles
            .is_empty()
    );
    assert!(
        store
            .check_permission(&scope, "other", BINDINGS_MANAGE_PERMISSION)
            .await
            .unwrap()
            .allowed
    );
    for role in ["Z", "a_", "a-", "A", "z"] {
        store
            .create_role(&scope, "other", role, role)
            .await
            .unwrap()
            .unwrap();
    }
    let page = store.list_roles(&scope, None, 100).await.unwrap().unwrap();
    let expected = vec!["A", "Z", "a-", "a_", BOOTSTRAP_ROLE_ID, "z"];
    assert_eq!(
        page.roles
            .iter()
            .map(|r| r.role_id.as_str())
            .collect::<Vec<_>>(),
        expected
    );
    let mut cursor = None;
    for role in expected {
        let page = store
            .list_roles(&scope, cursor.as_deref(), 1)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(page.roles[0].role_id, role);
        cursor = Some(role.to_owned());
    }
    for (role, permission) in [("A", "document.read"), ("Z", "document.write")] {
        store
            .set_role_permissions(
                &scope,
                "other",
                role,
                &BTreeSet::from([permission.to_owned()]),
            )
            .await
            .unwrap()
            .unwrap();
        store
            .assign_role(&scope, "other", "member", role)
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        store
            .check_permission(&scope, "member", "document.read")
            .await
            .unwrap()
            .allowed
    );
    assert!(
        store
            .check_permission(&scope, "member", "document.write")
            .await
            .unwrap()
            .allowed
    );
    store
        .revoke_role(&scope, "other", "member", "A")
        .await
        .unwrap()
        .unwrap();
    assert!(
        !store
            .check_permission(&scope, "member", "document.read")
            .await
            .unwrap()
            .allowed
    );
    assert!(
        store
            .check_permission(&scope, "member", "document.write")
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !store
            .bootstrap_scope(&scope, "owner")
            .await
            .unwrap()
            .unwrap()
            .created
    );
}
