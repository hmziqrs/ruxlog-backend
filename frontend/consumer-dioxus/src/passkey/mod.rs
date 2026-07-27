//! Browser WebAuthn (passkey) glue for the consumer app (issue #4).
//!
//! Thin wasm-bindgen bridge over the native `navigator.credentials.create` /
//! `.get` WebAuthn API. The server hands the browser a JSON challenge whose
//! byte-bearing fields (`challenge`, `user.id`, `*.id`) are base64url strings
//! (the `webauthn-rs` convention); the browser needs them as `BufferSource`.
//! This module does that conversion, drives the credential prompt, and returns
//! the authenticator's response serialized back to base64url strings — exactly
//! the shape the backend's webauthn-rs types deserialize from.
//!
//! Only available on `wasm32` (the browser). On non-browser targets the
//! helpers return an error / report unsupported so the screens that reference
//! them keep compiling for desktop/server.
//!
//! This module is gated behind `consumer-auth` in `main.rs`; the wasm JS
//! bindings additionally require the `web` feature set (which provides
//! `wasm-bindgen` / `js-sys` / `serde-wasm-bindgen`), the same way the
//! `analytics` Firebase bindings are wired.

// ── wasm32: real browser WebAuthn via inline JS ────────────────────────────
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inline_js = r#"
// base64url string -> ArrayBuffer (BufferSource). Pass-through if already a buffer.
function b64uToBuf(value) {
    if (value instanceof ArrayBuffer) return value;
    if (ArrayBuffer.isView(value)) return value.buffer;
    let s = String(value).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8.buffer;
}
// ArrayBuffer -> base64url string (no padding).
function bufToB64u(buf) {
    const u8 = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function webauthnSupported() {
    return typeof window !== 'undefined' && !!window.PublicKeyCredential;
}
export async function webauthnCreate(challengeResponse) {
    // Deep-clone so the conversion never mutates the caller's object.
    const pk = JSON.parse(JSON.stringify(challengeResponse.publicKey));
    pk.challenge = b64uToBuf(pk.challenge);
    if (pk.user && pk.user.id) pk.user.id = b64uToBuf(pk.user.id);
    if (Array.isArray(pk.excludeCredentials)) {
        pk.excludeCredentials.forEach(function (c) { c.id = b64uToBuf(c.id); });
    }
    const cred = await navigator.credentials.create({ publicKey: pk });
    const response = {
        attestationObject: bufToB64u(cred.response.attestationObject),
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
    };
    try { if (cred.response.getTransports) response.transports = cred.response.getTransports(); } catch (_) {}
    return {
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        type: cred.type,
        response: response,
    };
}
export async function webauthnGet(challengeResponse) {
    const pk = JSON.parse(JSON.stringify(challengeResponse.publicKey));
    pk.challenge = b64uToBuf(pk.challenge);
    if (Array.isArray(pk.allowCredentials)) {
        pk.allowCredentials.forEach(function (c) { c.id = b64uToBuf(c.id); });
    }
    const cred = await navigator.credentials.get({ publicKey: pk });
    const response = {
        authenticatorData: bufToB64u(cred.response.authenticatorData),
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        signature: bufToB64u(cred.response.signature),
    };
    try { if (cred.response.userHandle) response.userHandle = bufToB64u(cred.response.userHandle); } catch (_) {}
    return {
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        type: cred.type,
        response: response,
    };
}
"#)]
extern "C" {
    #[wasm_bindgen(js_name = webauthnSupported)]
    fn webauthn_supported() -> bool;
    #[wasm_bindgen(js_name = webauthnCreate)]
    async fn webauthn_create(challenge: JsValue) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = webauthnGet)]
    async fn webauthn_get(challenge: JsValue) -> Result<JsValue, JsValue>;
}

/// `true` iff the current browser supports WebAuthn passkeys. Always `false`
/// off the browser (desktop/server build targets).
pub fn is_supported() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        webauthn_supported()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}

/// Drive `navigator.credentials.create` for a registration challenge. The
/// argument is the server's `/register/begin` `challenge` value (a
/// `CreationChallengeResponse` JSON object). Returns the serialized
/// `PublicKeyCredential` ready to POST to `/register/finish`.
pub async fn create_credentials(
    challenge: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    #[cfg(target_arch = "wasm32")]
    {
        let js = serde_wasm_bindgen::to_value(challenge).map_err(|e| e.to_string())?;
        let res = webauthn_create(js)
            .await
            .map_err(|e| format!("WebAuthn create failed: {:?}", e))?;
        serde_wasm_bindgen::from_value(res).map_err(|e| e.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = challenge;
        Err("WebAuthn is only available in the browser".to_string())
    }
}

/// Drive `navigator.credentials.get` for a discoverable login challenge. The
/// argument is the server's `/login/begin` `challenge` value (a
/// `RequestChallengeResponse` JSON object). Returns the serialized
/// `PublicKeyCredential` ready to POST to `/login/finish`.
pub async fn get_credentials(challenge: &serde_json::Value) -> Result<serde_json::Value, String> {
    #[cfg(target_arch = "wasm32")]
    {
        let js = serde_wasm_bindgen::to_value(challenge).map_err(|e| e.to_string())?;
        let res = webauthn_get(js)
            .await
            .map_err(|e| format!("WebAuthn get failed: {:?}", e))?;
        serde_wasm_bindgen::from_value(res).map_err(|e| e.to_string())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = challenge;
        Err("WebAuthn is only available in the browser".to_string())
    }
}
