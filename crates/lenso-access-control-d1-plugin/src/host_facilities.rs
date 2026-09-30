//! Selected private event binding for the existing shared Access Control store.
use lenso::RuntimeFailure;
#[derive(Clone, Debug)]
pub struct EventStorageBinding {
    pub(crate) name: String,
    pub(crate) binding: crate::EventBinding,
}
#[cfg(not(target_arch = "wasm32"))]
pub fn state(_: &serde_json::Value) -> Result<EventStorageBinding, RuntimeFailure> {
    Err(RuntimeFailure::InvalidResolvedPlan {
        detail: "D1 Access Control requires Workers".into(),
    })
}
#[cfg(target_arch = "wasm32")]
pub fn state(value: &wasm_bindgen::JsValue) -> Result<EventStorageBinding, RuntimeFailure> {
    use wasm_bindgen::JsCast;
    let invalid = || RuntimeFailure::InvalidResolvedPlan {
        detail: "invalid Access Control event-owned D1 facility".into(),
    };
    let name = js_sys::Reflect::get(value, &wasm_bindgen::JsValue::from_str("name"))
        .map_err(|_| invalid())?
        .as_string()
        .ok_or_else(invalid)?;
    if name.is_empty()
        || name.len() > 128
        || !name.as_bytes()[0].is_ascii_alphabetic()
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(invalid());
    }
    let batch = js_sys::Reflect::get(value, &wasm_bindgen::JsValue::from_str("batch"))
        .map_err(|_| invalid())?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| invalid())?;
    Ok(EventStorageBinding {
        name,
        binding: crate::EventBinding(Some(std::rc::Rc::new(crate::workers::D1Binding(batch)))),
    })
}
