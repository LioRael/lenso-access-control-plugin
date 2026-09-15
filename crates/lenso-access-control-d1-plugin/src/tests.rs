use super::{schema, storage::D1Store};
use futures::future::LocalBoxFuture;
use lenso_access_control_core::{
    BOOTSTRAP_ROLE_ID,
    storage::{DomainFailure, ScopeKey, Store},
};
use lenso_migration_d1::{Error, Statement, Transport};
use serde_json::Value;
use std::{cell::RefCell, rc::Rc};

#[derive(Clone, Debug)]
struct Sqlite(Rc<RefCell<rusqlite::Connection>>);
impl Sqlite {
    fn new() -> Self {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("PRAGMA foreign_keys=ON").unwrap();
        Self(Rc::new(RefCell::new(db)))
    }
}
impl Transport for Sqlite {
    fn batch(
        &self,
        statements: Vec<Statement>,
    ) -> LocalBoxFuture<'_, Result<Vec<Vec<Value>>, Error>> {
        Box::pin(async move {
            let mut db = self.0.borrow_mut();
            let tx = db.transaction().map_err(|_| Error::Transport)?;
            let mut results = vec![];
            for stmt in statements {
                let mut query = tx
                    .prepare(&stmt.sql)
                    .unwrap_or_else(|e| panic!("{e}: {}", stmt.sql));
                let columns = query
                    .column_names()
                    .iter()
                    .map(|v| (*v).to_owned())
                    .collect::<Vec<_>>();
                let params = stmt
                    .params
                    .iter()
                    .map(|v| match v {
                        Value::Null => rusqlite::types::Value::Null,
                        Value::String(s) => rusqlite::types::Value::Text(s.clone()),
                        Value::Number(n) => rusqlite::types::Value::Integer(n.as_i64().unwrap()),
                        _ => panic!("unsupported binding"),
                    })
                    .collect::<Vec<_>>();
                let mut rows = query
                    .query(rusqlite::params_from_iter(params))
                    .map_err(|_| Error::Transport)?;
                let mut values = vec![];
                while let Some(row) = rows.next().map_err(|_| Error::Transport)? {
                    let mut obj = serde_json::Map::new();
                    for (i, key) in columns.iter().enumerate() {
                        let v = match row.get_ref(i).unwrap() {
                            rusqlite::types::ValueRef::Null => Value::Null,
                            rusqlite::types::ValueRef::Integer(n) => n.into(),
                            rusqlite::types::ValueRef::Text(s) => {
                                String::from_utf8(s.to_vec()).unwrap().into()
                            }
                            _ => panic!("unexpected SQL value"),
                        };
                        obj.insert(key.clone(), v);
                    }
                    values.push(Value::Object(obj));
                }
                results.push(values);
            }
            tx.commit().map_err(|_| Error::Transport)?;
            Ok(results)
        })
    }
}
#[test]
fn shared_postgres_d1_contract_vectors() {
    futures::executor::block_on(async {
        let db = Sqlite::new();
        schema::plan().unwrap().setup(&db).await.unwrap();
        lenso_access_control_core::conformance::exercise(&D1Store(db.clone()), "d1").await;
        assert_eq!(
            db.0.borrow()
                .query_row("SELECT count(*) FROM access_control_operation", [], |r| r
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            0
        );
    });
}
#[test]
fn runtime_verify_never_installs_schema_and_rejects_history_drift() {
    futures::executor::block_on(async {
        let db = Sqlite::new();
        assert!(matches!(
            schema::plan().unwrap().verify(&db).await,
            Err(Error::SetupRequired)
        ));
        assert_eq!(
            db.0.borrow()
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        schema::plan().unwrap().setup(&db).await.unwrap();
        db.0.borrow()
            .execute("UPDATE _lenso_migrations SET checksum='drift'", [])
            .unwrap();
        assert!(matches!(
            schema::plan().unwrap().verify(&db).await,
            Err(Error::History)
        ));
    });
}
#[test]
fn rollback_preserves_policy_and_revision_on_late_failure() {
    futures::executor::block_on(async {
        let db = Sqlite::new();
        schema::plan().unwrap().setup(&db).await.unwrap();
        let store = D1Store(db.clone());
        let scope = ScopeKey {
            kind: "org".into(),
            id: "rollback".into(),
        };
        store
            .bootstrap_scope(&scope, "owner")
            .await
            .unwrap()
            .unwrap();
        db.0.borrow().execute_batch("CREATE TRIGGER reject_revision BEFORE UPDATE ON access_control_scopes BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
        assert!(
            store
                .create_role(&scope, "owner", "viewer", "Viewer")
                .await
                .is_err()
        );
        assert_eq!(
            store.get_role(&scope, "viewer").await.unwrap(),
            Err(DomainFailure::RoleNotFound)
        );
        assert_eq!(
            store
                .get_role(&scope, BOOTSTRAP_ROLE_ID)
                .await
                .unwrap()
                .unwrap()
                .1,
            1
        );
        assert_eq!(
            db.0.borrow()
                .query_row("SELECT count(*) FROM access_control_operation", [], |r| r
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            0
        );
    });
}
#[test]
fn large_revisions_round_trip_as_decimal_text_and_overflow_rolls_back() {
    futures::executor::block_on(async {
        let db = Sqlite::new();
        schema::plan().unwrap().setup(&db).await.unwrap();
        let store = D1Store(db.clone());
        let scope = ScopeKey {
            kind: "org".into(),
            id: "large".into(),
        };
        store
            .bootstrap_scope(&scope, "owner")
            .await
            .unwrap()
            .unwrap();
        db.0.borrow()
            .execute(
                "UPDATE access_control_scopes SET policy_revision=9007199254740993",
                [],
            )
            .unwrap();
        assert_eq!(
            store
                .create_role(&scope, "owner", "viewer", "Viewer")
                .await
                .unwrap()
                .unwrap()
                .revision,
            9_007_199_254_740_994
        );
        db.0.borrow()
            .execute(
                "UPDATE access_control_scopes SET policy_revision=9223372036854775807",
                [],
            )
            .unwrap();
        assert!(
            store
                .create_role(&scope, "owner", "overflow", "Overflow")
                .await
                .is_err()
        );
        assert_eq!(
            store.get_role(&scope, "overflow").await.unwrap(),
            Err(DomainFailure::RoleNotFound)
        );
    });
}
