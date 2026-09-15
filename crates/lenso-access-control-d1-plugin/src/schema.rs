use lenso_migration::{Migration, sql_migrations};
use lenso_migration_d1::{Plan, SqlMigration};
const MIGRATIONS: &[Migration] = sql_migrations![(
    1,
    "create-access-control",
    "migrations/d1/001_create_access_control.sql"
)];
const SQL: &[SqlMigration] = &[SqlMigration {
    migration: MIGRATIONS[0],
    statement_ends: include!("migration_statement_ends.rs"),
}];
pub fn plan() -> Result<Plan, lenso_migration_d1::Error> {
    Plan::new("lenso.access-control.d1", SQL, MIGRATIONS, None)
}
