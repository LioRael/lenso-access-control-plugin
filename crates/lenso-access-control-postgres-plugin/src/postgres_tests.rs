use std::collections::BTreeSet;

use lenso_postgres_kit::OwnedPostgres;
use sqlx::{AssertSqlSafe, Connection};
use url::Url;

use super::{
    AccessControlOperator, BINDINGS_MANAGE_PERMISSION, BOOTSTRAP_ROLE_ID, ROLES_MANAGE_PERMISSION,
    schema,
    storage::{self, DomainFailure, ScopeKey},
};

#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn durable_policy_preserves_union_revision_and_bootstrap_protection() {
    let Some(database_url) = std::env::var("LENSO_ACCESS_CONTROL_TEST_DATABASE_URL").ok() else {
        eprintln!(
            "skipping PostgreSQL acceptance; LENSO_ACCESS_CONTROL_TEST_DATABASE_URL is unset"
        );
        return;
    };
    let parsed = Url::parse(&database_url).expect("test database URL must be valid");
    let database = parsed.path().trim_start_matches('/');
    assert!(
        database.starts_with("lenso_access_control_test"),
        "acceptance requires a disposable lenso_access_control_test* database"
    );

    let schema_name = format!("access_control_acceptance_{}", std::process::id());
    let mut cleanup = sqlx::PgConnection::connect(&database_url).await.unwrap();
    let drop_schema = format!("DROP SCHEMA IF EXISTS {schema_name} CASCADE");
    sqlx::query(AssertSqlSafe(drop_schema.as_str()))
        .execute(&mut cleanup)
        .await
        .unwrap();
    AccessControlOperator::setup(&database_url, &schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.as_str()).unwrap(),
    )
    .await
    .unwrap();
    let scope = ScopeKey {
        kind: "organization".to_owned(),
        id: "org_42".to_owned(),
    };

    let bootstrap = storage::bootstrap_scope(&postgres, &scope, "usr_owner")
        .await
        .unwrap()
        .unwrap();
    assert!(bootstrap.created);
    assert_eq!(bootstrap.revision, 1);
    let repeated = storage::bootstrap_scope(&postgres, &scope, "usr_owner")
        .await
        .unwrap()
        .unwrap();
    assert!(!repeated.created);
    assert_eq!(repeated.revision, 1);
    assert_eq!(
        storage::bootstrap_scope(&postgres, &scope, "usr_other")
            .await
            .unwrap(),
        Err(DomainFailure::ScopeAlreadyBootstrapped)
    );

    let viewer = storage::create_role(&postgres, &scope, "usr_owner", "viewer", "Viewer")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(viewer.revision, 2);
    let viewer_permissions = storage::set_role_permissions(
        &postgres,
        &scope,
        "usr_owner",
        "viewer",
        &BTreeSet::from(["document.read".to_owned()]),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(viewer_permissions.revision, 3);
    let assigned = storage::assign_role(&postgres, &scope, "usr_owner", "usr_member", "viewer")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(assigned.revision, 4);

    storage::create_role(&postgres, &scope, "usr_owner", "editor", "Editor")
        .await
        .unwrap()
        .unwrap();
    storage::set_role_permissions(
        &postgres,
        &scope,
        "usr_owner",
        "editor",
        &BTreeSet::from(["document.write".to_owned()]),
    )
    .await
    .unwrap()
    .unwrap();
    storage::assign_role(&postgres, &scope, "usr_owner", "usr_member", "editor")
        .await
        .unwrap()
        .unwrap();

    let read = storage::check_permission(&postgres, &scope, "usr_member", "document.read")
        .await
        .unwrap();
    let write = storage::check_permission(&postgres, &scope, "usr_member", "document.write")
        .await
        .unwrap();
    assert!(read.allowed && write.allowed);
    assert_eq!(read.revision, 7);
    assert_eq!(write.revision, 7);
    let missing = storage::check_permission(&postgres, &scope, "usr_missing", "document.read")
        .await
        .unwrap();
    assert!(!missing.allowed);
    assert_eq!(missing.revision, 7);

    let unchanged = storage::assign_role(&postgres, &scope, "usr_owner", "usr_member", "viewer")
        .await
        .unwrap()
        .unwrap();
    assert!(!unchanged.changed);
    assert_eq!(unchanged.revision, 7);
    assert_eq!(
        storage::set_role_permissions(
            &postgres,
            &scope,
            "usr_owner",
            BOOTSTRAP_ROLE_ID,
            &BTreeSet::from([
                ROLES_MANAGE_PERMISSION.to_owned(),
                BINDINGS_MANAGE_PERMISSION.to_owned(),
            ]),
        )
        .await
        .unwrap(),
        Err(DomainFailure::ProtectedRole)
    );
    assert_eq!(
        storage::revoke_role(
            &postgres,
            &scope,
            "usr_owner",
            "usr_owner",
            BOOTSTRAP_ROLE_ID,
        )
        .await
        .unwrap(),
        Err(DomainFailure::ProtectedBinding)
    );

    let delegated = storage::assign_role(
        &postgres,
        &scope,
        "usr_owner",
        "usr_successor",
        BOOTSTRAP_ROLE_ID,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(delegated.revision, 8);
    let transferred = storage::revoke_role(
        &postgres,
        &scope,
        "usr_owner",
        "usr_owner",
        BOOTSTRAP_ROLE_ID,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(transferred.revision, 9);
    let repeated_after_transfer = storage::bootstrap_scope(&postgres, &scope, "usr_owner")
        .await
        .unwrap()
        .unwrap();
    assert!(!repeated_after_transfer.created);
    assert_eq!(repeated_after_transfer.revision, 9);

    postgres.pool().close().await;
    sqlx::query(AssertSqlSafe(
        format!("DROP SCHEMA {schema_name} CASCADE").as_str(),
    ))
    .execute(&mut cleanup)
    .await
    .unwrap();
}
