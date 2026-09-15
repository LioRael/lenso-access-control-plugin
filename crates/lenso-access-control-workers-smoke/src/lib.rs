//! Local real-Adapter qualification; all assertion keys and subjects are fixtures.
#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use lenso_access_control_d1_plugin::{self as plugin, workers::D1Binding};
use lenso_app_plan::{
    AppComposition, CapabilityBinding, CapabilityEndpointPlan, CapabilityRequirementPlan,
    PluginInstancePlan,
};
use lenso_auth_sdk::{ActorAssertionIssuer, Validity, audience};
use lenso_capability_access_control as access;
use lenso_capability_access_control_admin as admin;
use lenso_capability_access_control_directory as directory;
use lenso_kernel::{CancellationToken, Kernel, RuntimeFailure, ShutdownOutcome};
use lenso_native_adapter::{
    NativePluginFactory, NativePluginFactoryContext, NativePluginInstance, NativePluginRegistry,
};
use lenso_workers_driver::WorkersDriver;
use serde_json::json;
use std::time::Duration;
use wasm_bindgen::prelude::*;

#[derive(Debug)]
struct Caller;
impl NativePluginFactory for Caller {
    fn package_id(&self) -> &'static str {
        "test.access-caller"
    }
    fn instantiate(
        &self,
        _: NativePluginFactoryContext<'_>,
    ) -> Result<NativePluginInstance, RuntimeFailure> {
        Ok(NativePluginInstance::default())
    }
}
struct Event(WorkersDriver);
impl Drop for Event {
    fn drop(&mut self) {
        self.0.request_shutdown();
    }
}
#[track_caller]
fn failure() -> JsValue {
    JsValue::from_str(&format!(
        "Access Control qualification failed at {}",
        std::panic::Location::caller()
    ))
}
#[wasm_bindgen]
pub async fn migrate(batch: js_sys::Function) -> Result<(), JsValue> {
    plugin::schema::plan()
        .map_err(|_| failure())?
        .setup(&D1Binding(batch))
        .await
        .map_err(|_| failure())
}

#[wasm_bindgen]
#[allow(clippy::too_many_lines)]
pub async fn exercise(
    batch: js_sys::Function,
    mode: String,
    id: String,
    close: js_sys::Function,
) -> Result<String, JsValue> {
    let issuer = ActorAssertionIssuer::new("auth.test", b"access-control-workers-fixture");
    let config = json!({"binding":"ACCESS","auth_issuer":"auth.test","auth_assertion_public_key":issuer.public_key_base64(),"bootstrap_callers":["caller"],"directory_callers":["caller"]});
    let mut caller = PluginInstancePlan::new("caller", "test.access-caller");
    let mut provider = PluginInstancePlan::new("access", plugin::PACKAGE_ID)
        .with_configuration(config.to_string());
    let mut bindings = vec![];
    for (cap, version, mut ops) in [
        (
            access::CAPABILITY_ID,
            access::DESCRIPTOR_VERSION,
            vec![access::CHECK_PERMISSION_OPERATION],
        ),
        (
            admin::CAPABILITY_ID,
            admin::DESCRIPTOR_VERSION,
            vec![
                admin::BOOTSTRAP_SCOPE_OPERATION,
                admin::CREATE_ROLE_OPERATION,
                admin::ASSIGN_ROLE_OPERATION,
                admin::REVOKE_ROLE_OPERATION,
                admin::DELETE_ROLE_OPERATION,
                admin::SET_ROLE_PERMISSIONS_OPERATION,
            ],
        ),
        (
            directory::CAPABILITY_ID,
            directory::DESCRIPTOR_VERSION,
            vec![
                directory::GET_ROLE_OPERATION,
                directory::LIST_ROLES_OPERATION,
                directory::LIST_SUBJECT_ROLES_OPERATION,
            ],
        ),
    ] {
        ops.sort_unstable();
        caller = caller.with_requirement(CapabilityRequirementPlan::one(cap, version));
        provider = provider.with_capability(CapabilityEndpointPlan::new(cap, version, ops));
        bindings.push(CapabilityBinding::new("caller", cap, version, "access"));
    }
    let plan = AppComposition::new(vec![caller, provider], bindings)
        .resolve()
        .map_err(|_| failure())?;
    let driver = WorkersDriver::new();
    let _event = Event(driver.clone());
    let started = Kernel::start_native(
        plan,
        driver.clone(),
        NativePluginRegistry::new()
            .with_factory(Caller)
            .with_factory(plugin::workers::factory(
                if mode == "wrong-binding" {
                    "WRONG"
                } else {
                    "ACCESS"
                },
                batch.clone(),
            )),
    )
    .await;
    if matches!(
        mode.as_str(),
        "missing-schema" | "wrong-binding" | "throws" | "malformed"
    ) {
        return if started.is_err() {
            Ok("startup-rejected".into())
        } else {
            Err(failure())
        };
    }
    let app = started.map_err(|error| JsValue::from_str(&format!("startup: {error:?}")))?;
    if mode == "conformance" {
        lenso_access_control_core::conformance::exercise(
            &plugin::storage::D1Store(D1Binding(batch)),
            &id,
        )
        .await;
    } else {
        let subject = "owner";
        let boot = app
            .invoke::<admin::AccessControlAdminBootstrapScope>(
                "caller",
                admin::BOOTSTRAP_SCOPE_OPERATION,
                admin::BootstrapScopeRequest {
                    scope: admin::BootstrapScopeRequestScope {
                        kind: "org".into(),
                        id: id.clone(),
                    },
                    subject: subject.into(),
                },
            )
            .await
            .map_err(|_| failure())?
            .map_err(|_| failure())?;
        if boot.policy_revision != "1" {
            return Err(failure());
        }
        let now = time::OffsetDateTime::now_utc();
        let assertion = issuer.issue(
            subject,
            "user",
            "strong",
            [audience(
                admin::CAPABILITY_ID,
                if mode == "wrong-audience" {
                    admin::DELETE_ROLE_OPERATION
                } else {
                    admin::CREATE_ROLE_OPERATION
                },
            )],
            Validity::new(
                now - time::Duration::minutes(2),
                if mode == "expired" {
                    now - time::Duration::minutes(1)
                } else {
                    now + time::Duration::minutes(1)
                },
            )
            .map_err(|_| failure())?,
            Default::default(),
        );
        let context = assertion
            .attach(app.invocation_context_after(Duration::from_secs(10), CancellationToken::new()))
            .map_err(|_| failure())?;
        if mode == "closed" {
            close.call0(&JsValue::UNDEFINED).map_err(|_| failure())?;
        }
        let created = app
            .invoke_with_context::<admin::AccessControlAdminCreateRole>(
                "caller",
                admin::CREATE_ROLE_OPERATION,
                context,
                admin::CreateRoleRequest {
                    scope: admin::CreateRoleRequestScope {
                        kind: "org".into(),
                        id: id.clone(),
                    },
                    role_id: "viewer".into(),
                    name: "Viewer".into(),
                },
            )
            .await;
        match mode.as_str() {
            "closed" => {
                if !matches!(created, Err(RuntimeFailure::PluginFailure { .. })) {
                    return Err(failure());
                }
            }
            "wrong-audience" | "expired" => {
                if !matches!(created, Ok(Err(admin::CreateRoleError::Unauthenticated))) {
                    return Err(failure());
                }
            }
            _ => {
                if created
                    .map_err(|_| failure())?
                    .map_err(|_| failure())?
                    .policy_revision
                    != "2"
                {
                    return Err(failure());
                }
            }
        }
        if mode != "closed" {
            let page = app
                .invoke::<directory::AccessControlDirectoryListRoles>(
                    "caller",
                    directory::LIST_ROLES_OPERATION,
                    directory::ListRolesRequest {
                        scope: directory::Scope {
                            kind: "org".into(),
                            id: id.clone(),
                        },
                        cursor: None,
                        limit: 10,
                    },
                )
                .await
                .map_err(|_| failure())?
                .map_err(|_| failure())?;
            if page.roles.len()
                != if matches!(mode.as_str(), "wrong-audience" | "expired") {
                    1
                } else {
                    2
                }
            {
                return Err(failure());
            }
        }
    }
    if app.shutdown(Duration::from_secs(1)).await != ShutdownOutcome::Clean {
        return Err(failure());
    }
    let plan = AppComposition::new(
        vec![PluginInstancePlan::new("caller", "test.access-caller")],
        vec![],
    )
    .resolve()
    .map_err(|_| failure())?;
    let remaining = Kernel::start_native(
        plan,
        driver,
        NativePluginRegistry::new().with_factory(Caller),
    )
    .await
    .map_err(|_| failure())?;
    if remaining.shutdown(Duration::from_secs(1)).await != ShutdownOutcome::Clean {
        return Err(failure());
    }
    Ok("passed".into())
}

/// Storage races run through the exact Wasm implementation and real primary D1 batches.
#[wasm_bindgen]
pub async fn race(batch: js_sys::Function, mode: String, id: String) -> Result<String, JsValue> {
    use lenso_access_control_core::{BOOTSTRAP_ROLE_ID, storage::*};
    let store = plugin::storage::D1Store(D1Binding(batch));
    let scope = ScopeKey {
        kind: "race".into(),
        id,
    };
    let result = match mode.as_str() {
        "race-setup" => {
            store
                .bootstrap_scope(&scope, "owner")
                .await
                .map_err(|_| failure())?
                .map_err(|_| failure())?;
            let v = store
                .assign_role(&scope, "owner", "other", BOOTSTRAP_ROLE_ID)
                .await
                .map_err(|_| failure())?
                .map_err(|_| failure())?;
            json!({"revision":v.revision.to_string()})
        }
        "race-create" => match store
            .create_role(&scope, "owner", "viewer", "Viewer")
            .await
            .map_err(|_| failure())?
        {
            Ok(v) => json!({"revision":v.revision.to_string(),"allowed":true}),
            Err(DomainFailure::Forbidden) => json!({"allowed":false}),
            _ => return Err(failure()),
        },
        "race-revoke" => {
            let v = store
                .revoke_role(&scope, "other", "owner", BOOTSTRAP_ROLE_ID)
                .await
                .map_err(|_| failure())?
                .map_err(|_| failure())?;
            json!({"revision":v.revision.to_string(),"changed":v.changed})
        }
        "race-assign" => {
            let v = store
                .assign_role(&scope, "other", "third", BOOTSTRAP_ROLE_ID)
                .await
                .map_err(|_| failure())?
                .map_err(|_| failure())?;
            json!({"revision":v.revision.to_string(),"changed":v.changed})
        }
        _ => return Err(failure()),
    };
    Ok(result.to_string())
}
