//! FCM device-token registration hook.
//!
//! Obtaining an FCM registration token requires the Firebase Messaging JS SDK,
//! which is NOT bundled with this app (the Firebase compat SDK is loaded
//! externally by the host page when configured). This hook therefore:
//!
//! 1. Is gated behind the `analytics` feature (the existing Firebase wiring)
//!    AND `consumer-auth` (registration needs a logged-in session + CSRF).
//! 2. On wasm32, probes `window.firebase.messaging`; if present it asks the JS
//!    SDK for a token and registers it via the `device` store
//!    (`POST /device/v1/register`). If messaging is unavailable it logs and
//!    no-ops — in-app notifications still work without push.
//! 3. On non-wasm targets (or when the features are off) it is a no-op.
//!
//! The plumbing compiles regardless of whether the JS SDK is present at runtime.

/// Register the current browser/device FCM token with the backend, if the
/// Firebase Messaging JS SDK is available. Call once from a top-level component
/// (e.g. the navbar) behind `#[cfg(all(feature = "analytics", feature = "consumer-auth"))]`.
#[cfg(all(feature = "analytics", feature = "consumer-auth"))]
pub fn use_device_registration() {
    use dioxus::logger::tracing;
    use dioxus::prelude::*;

    use_effect(move || {
        spawn(async move {
            // Only register when the user is actually logged in.
            let auth = ruxlog_shared::use_auth();
            let logged_in = auth.user.read().is_some();
            if !logged_in {
                return;
            }

            #[cfg(target_arch = "wasm32")]
            {
                match get_fcm_token().await {
                    Some(token) => {
                        tracing::info!("Registering FCM device token with backend");
                        ruxlog_shared::use_device()
                            .register(token, "web".to_string())
                            .await;
                    }
                    None => {
                        // Firebase Messaging SDK not present at runtime — in-app
                        // notifications still work; push is simply skipped.
                        tracing::info!("FCM messaging unavailable; skipping device registration");
                    }
                }
            }

            #[cfg(not(target_arch = "wasm32"))]
            {
                tracing::info!(
                    "FCM device registration is only available on the web build; skipping"
                );
            }
        });
    });
}

/// Non-wasm / non-feature stub so the hook symbol always exists for the navbar
/// call site regardless of which features are enabled. The analytics +
/// consumer-auth gate above is what actually drives registration.
#[cfg(not(all(feature = "analytics", feature = "consumer-auth")))]
pub fn use_device_registration() {}

// ── wasm-only JS interop ──────────────────────────────────────────────────

/// Resolve the FCM registration token from `window.firebase.messaging().getToken()`.
///
/// Returns `None` if the global `firebase` SDK, its `messaging` service, or the
/// token promise is unavailable/rejected — i.e. push is not configured.
#[cfg(all(
    target_arch = "wasm32",
    feature = "analytics",
    feature = "consumer-auth"
))]
async fn get_fcm_token() -> Option<String> {
    use js_sys::Reflect;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;

    let window = web_sys::window()?;

    // window.firebase (Firebase compat SDK global).
    let firebase = Reflect::get(&window, &"firebase".into()).ok()?;
    if firebase.is_undefined() || firebase.is_null() {
        return None;
    }

    // firebase.messaging (function returning the Messaging instance).
    let messaging_fn = Reflect::get(&firebase, &"messaging".into()).ok()?;
    let messaging_fn = messaging_fn.dyn_ref::<js_sys::Function>()?;
    let messaging = messaging_fn.call0(&firebase).ok()?;

    // messaging.getToken() returns a Promise<String>.
    let get_token_val = Reflect::get(&messaging, &"getToken".into()).ok()?;
    let get_token_fn = get_token_val.dyn_ref::<js_sys::Function>()?;
    let token_promise_val = get_token_fn.call0(&messaging).ok()?;
    let token_promise = token_promise_val.dyn_into::<js_sys::Promise>().ok()?;

    let token_js = JsFuture::from(token_promise).await.ok()?;
    token_js.as_string()
}
