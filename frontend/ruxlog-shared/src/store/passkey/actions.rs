use super::{
    ListResponse, LoginBeginResponse, LoginFinishPayload, LoginFinishResponse, PasskeyCredential,
    PasskeyState, RegisterBeginResponse, RegisterFinishPayload,
};
use oxcore::http;
use oxstore::state_request_abstraction;

impl PasskeyState {
    /// `POST /passkey/v1/register/begin` — returns the WebAuthn challenge +
    /// opaque registration state. The caller hands `challenge` to the browser
    /// WebAuthn API and carries both values into [`Self::register_finish`].
    pub async fn register_begin(&self) -> Option<RegisterBeginResponse> {
        // No payload — the authenticated user is resolved server-side.
        state_request_abstraction(
            &self.register_begin,
            None::<()>,
            http::post("/passkey/v1/register/begin", &serde_json::json!({})).send(),
            "passkey_register_begin",
            |resp: &RegisterBeginResponse| (Some(Some(resp.clone())), None),
        )
        .await
    }

    /// `POST /passkey/v1/register/finish` — verifies the authenticator
    /// response and persists the new credential. Returns the credential view.
    pub async fn register_finish(
        &self,
        payload: RegisterFinishPayload,
    ) -> Option<PasskeyCredential> {
        state_request_abstraction(
            &self.register,
            None::<()>,
            http::post("/passkey/v1/register/finish", &payload).send(),
            "passkey_register_finish",
            |resp: &PasskeyCredential| (Some(Some(resp.clone())), None),
        )
        .await
    }

    /// `POST /passkey/v1/list` — lists the user's registered passkeys.
    pub async fn list(&self) -> Option<ListResponse> {
        state_request_abstraction(
            &self.list,
            None::<()>,
            http::post("/passkey/v1/list", &serde_json::json!({})).send(),
            "passkey_list",
            |resp: &ListResponse| (Some(resp.data.clone()), None),
        )
        .await
    }

    /// `POST /passkey/v1/remove` — deletes a credential by its base64url id.
    pub async fn remove(&self, credential_id: String) {
        let _ = state_request_abstraction(
            &self.remove,
            None::<()>,
            http::post(
                "/passkey/v1/remove",
                &serde_json::json!({ "credential_id": credential_id }),
            )
            .send(),
            "passkey_remove",
            |_resp: &serde_json::Value| (Some(Some(())), None),
        )
        .await;
    }

    /// `POST /passkey/v1/login/begin` — returns the discoverable-login
    /// challenge + opaque authentication state. No user is identified up front;
    /// the authenticator returns the credential, which the server resolves.
    pub async fn login_begin(&self) -> Option<LoginBeginResponse> {
        state_request_abstraction(
            &self.login_begin,
            None::<()>,
            http::post("/passkey/v1/login/begin", &serde_json::json!({})).send(),
            "passkey_login_begin",
            |resp: &LoginBeginResponse| (Some(Some(resp.clone())), None),
        )
        .await
    }

    /// `POST /passkey/v1/login/finish` — verifies the assertion and issues the
    /// session (cookie). Returns the authenticated user so the caller can
    /// populate the auth store; the session cookie is set regardless.
    pub async fn login_finish(&self, payload: LoginFinishPayload) -> Option<LoginFinishResponse> {
        state_request_abstraction(
            &self.login,
            None::<()>,
            http::post("/passkey/v1/login/finish", &payload).send(),
            "passkey_login_finish",
            |resp: &LoginFinishResponse| (Some(Some(resp.user.clone())), None),
        )
        .await
    }
}
