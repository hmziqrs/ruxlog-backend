use std::collections::HashMap;

use dioxus::prelude::*;
use validator::Validate;

use crate::hooks::{OxForm, OxFormModel};
use crate::router::Route;
use oxui::components::animated_grid::{AnimatedGridBackground, AnimatedGridCircles, GridContext};
use oxui::components::error::{ErrorDetails, ErrorDetailsVariant};
use oxui::components::form::input::AppInput;
use oxui::shadcn::button::Button;
use ruxlog_shared::store::password_reset::{
    RequestResetPayload, ResetPasswordPayload, VerifyResetPayload,
};
use ruxlog_shared::store::use_password_reset;

/// Form model backing the three-step recovery screen. Every field the user can
/// type across all three steps lives here; each step renders only the inputs it
/// needs and reads the relevant field on submit.
#[derive(Debug, Validate, Clone, PartialEq)]
pub struct ForgotPasswordForm {
    #[validate(email(message = "Please enter a valid email address"))]
    pub email: String,

    #[validate(length(min = 6, max = 6, message = "Code must be 6 digits"))]
    pub code: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,

    #[validate(length(min = 8, message = "Please confirm your new password"))]
    pub confirm_password: String,
}

impl Default for ForgotPasswordForm {
    fn default() -> Self {
        Self::new()
    }
}

impl ForgotPasswordForm {
    pub fn new() -> Self {
        ForgotPasswordForm {
            email: String::new(),
            code: String::new(),
            password: String::new(),
            confirm_password: String::new(),
        }
    }

    pub fn dev() -> Self {
        Self::new()
    }
}

impl OxFormModel for ForgotPasswordForm {
    fn to_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("email".to_string(), self.email.clone());
        map.insert("code".to_string(), self.code.clone());
        map.insert("password".to_string(), self.password.clone());
        map.insert(
            "confirm_password".to_string(),
            self.confirm_password.clone(),
        );
        map
    }

    fn update_field(&mut self, name: String, value: &str) {
        match name.as_str() {
            "email" => self.email = value.to_string(),
            "code" => self.code = value.to_string(),
            "password" => self.password = value.to_string(),
            "confirm_password" => self.confirm_password = value.to_string(),
            _ => {}
        }
    }
}

fn use_forgot_password_form(
    initial_state: ForgotPasswordForm,
) -> Signal<OxForm<ForgotPasswordForm>> {
    use_signal(|| OxForm::new(initial_state))
}

/// Three-step password recovery flow (issue #43):
///   1. Request a reset code by email.
///   2. Verify the code → the backend issues a single-use `reset_token`.
///   3. Reset the password, presenting that `reset_token`.
///
/// The `reset_token` returned by the verify step is the only credential the
/// backend will accept for the final reset (the emailed code is consumed at
/// verify time — audit F#9), so it is threaded through local screen state
/// between steps. Mirrors the consumer forgot-password screen.
#[derive(PartialEq, Eq, Clone, Copy)]
enum ForgotStep {
    RequestCode,
    VerifyCode,
    ResetPassword,
}

#[component]
pub fn ForgotPasswordScreen() -> Element {
    let ox_form = use_forgot_password_form(ForgotPasswordForm::dev());
    let password_reset = use_password_reset();
    let nav = use_navigator();

    let mut step = use_signal(|| ForgotStep::RequestCode);
    // Opaque single-use token issued by the verify step. Carried into the
    // reset step; never sent back to the client after consume.
    let mut reset_token = use_signal(String::new);
    let mut password_match_error = use_signal(|| Option::<String>::None);

    use_context_provider(GridContext::new);

    // Start each visit clean so stale errors/tokens from a prior attempt don't
    // leak into a new one. `use_effect` reads no signals, so it runs only once
    // after the initial mount.
    use_effect(move || {
        password_reset.reset();
    });

    let request_frame = password_reset.request.read();
    let verify_frame = password_reset.verify.read();
    let reset_frame = password_reset.reset.read();

    rsx! {
        div { class: "relative flex items-center justify-center min-h-screen overflow-hidden transition-colors duration-300",
            AnimatedGridBackground {}
            AnimatedGridCircles {}
            div { class: "relative z-10 flex w-full justify-center",
                div { class: "relative w-full max-w-md p-8 space-y-6 rounded-2xl backdrop-blur-sm border border-zinc-200 dark:border-zinc-800 bg-white/80 dark:bg-zinc-900/80 transition-colors duration-300",
                    div { class: "flex justify-center mb-2",
                        img {
                            class: "h-26 w-26",
                            src: asset!("/assets/logo.png"),
                            alt: "Logo",
                        }
                    }
                    h1 { class: "text-3xl font-extrabold text-center text-zinc-800 dark:text-zinc-100 tracking-tight transition-colors duration-300",
                        "Reset your password"
                    }

                    // ---- Step 1: request a code by email ----
                    if step() == ForgotStep::RequestCode {
                        form { class: "space-y-5",
                            onsubmit: |e: Event<FormData>| {
                                e.prevent_default();
                            },
                            p { class: "text-sm text-center text-zinc-600 dark:text-zinc-400 transition-colors duration-300",
                                "Enter your account email and we'll send a verification code."
                            }
                            AppInput {
                                name: "email",
                                form: ox_form,
                                label: "Email",
                                placeholder: "Enter your email",
                                r#type: "email",
                            }
                            if request_frame.is_failed() {
                                ErrorDetails {
                                    error: request_frame.error.clone(),
                                    variant: ErrorDetailsVariant::Minimum,
                                    class: "mb-2",
                                }
                            }
                            if request_frame.is_success() {
                                div { class: "p-3 rounded-lg bg-green-500/10 border border-green-500/50 text-sm",
                                    "If an account exists for that email, a verification code is on its way."
                                }
                            }
                            Button {
                                class: "w-full",
                                disabled: request_frame.is_loading(),
                                onclick: move |e: Event<MouseData>| {
                                    e.prevent_default();
                                    let email = ox_form.read().data.email.clone();
                                    spawn(async move {
                                        password_reset
                                            .request(RequestResetPayload { email })
                                            .await;
                                        if password_reset.request.read().is_success() {
                                            step.set(ForgotStep::VerifyCode);
                                        }
                                    });
                                },
                                if request_frame.is_loading() {
                                    div { class: "loading loading-spinner loading-xs" }
                                }
                                span { "Send verification code" }
                            }
                        }
                    }

                    // ---- Step 2: verify the code → obtain reset_token ----
                    if step() == ForgotStep::VerifyCode {
                        form { class: "space-y-5",
                            onsubmit: |e: Event<FormData>| {
                                e.prevent_default();
                            },
                            p { class: "text-sm text-center text-zinc-600 dark:text-zinc-400 transition-colors duration-300",
                                "Enter the 6-digit code we sent to your email."
                            }
                            AppInput {
                                name: "email",
                                form: ox_form,
                                label: "Email",
                                placeholder: "Enter your email",
                                r#type: "email",
                                readonly: true,
                            }
                            AppInput {
                                name: "code",
                                form: ox_form,
                                label: "Verification code",
                                placeholder: "123456",
                            }
                            if verify_frame.is_failed() {
                                ErrorDetails {
                                    error: verify_frame.error.clone(),
                                    variant: ErrorDetailsVariant::Minimum,
                                    class: "mb-2",
                                }
                            }
                            Button {
                                class: "w-full",
                                disabled: verify_frame.is_loading(),
                                onclick: move |e: Event<MouseData>| {
                                    e.prevent_default();
                                    let email = ox_form.read().data.email.clone();
                                    let code = ox_form.read().data.code.clone();
                                    spawn(async move {
                                        password_reset
                                            .verify(VerifyResetPayload { email, code })
                                            .await;
                                        // verify is single-use; the response carries the
                                        // reset_token we must present at the reset step.
                                        if let Some(Some(resp)) =
                                            password_reset.verify.read().data.clone()
                                        {
                                            reset_token.set(resp.reset_token);
                                            step.set(ForgotStep::ResetPassword);
                                        }
                                    });
                                },
                                if verify_frame.is_loading() {
                                    div { class: "loading loading-spinner loading-xs" }
                                }
                                span { "Verify code" }
                            }
                            button {
                                class: "w-full text-sm text-zinc-500 hover:underline",
                                r#type: "button",
                                onclick: move |_| {
                                    step.set(ForgotStep::RequestCode);
                                },
                                "Use a different email"
                            }
                        }
                    }

                    // ---- Step 3: reset the password ----
                    if step() == ForgotStep::ResetPassword {
                        form { class: "space-y-5",
                            onsubmit: |e: Event<FormData>| {
                                e.prevent_default();
                            },
                            p { class: "text-sm text-center text-zinc-600 dark:text-zinc-400 transition-colors duration-300",
                                "Choose a new password for your account."
                            }
                            AppInput {
                                name: "password",
                                form: ox_form,
                                label: "New password",
                                placeholder: "At least 8 characters",
                                r#type: "password",
                            }
                            AppInput {
                                name: "confirm_password",
                                form: ox_form,
                                label: "Confirm new password",
                                placeholder: "Re-enter your new password",
                                r#type: "password",
                            }
                            if let Some(error) = password_match_error() {
                                div { class: "p-3 rounded-lg bg-red-500/10 border border-red-500/50 text-sm",
                                    "{error}"
                                }
                            }
                            if reset_frame.is_failed() {
                                ErrorDetails {
                                    error: reset_frame.error.clone(),
                                    variant: ErrorDetailsVariant::Minimum,
                                    class: "mb-2",
                                }
                            }
                            Button {
                                class: "w-full",
                                disabled: reset_frame.is_loading(),
                                onclick: move |e: Event<MouseData>| {
                                    e.prevent_default();
                                    let (password, confirm_password) = {
                                        let form_data = ox_form.read();
                                        (form_data.data.password.clone(), form_data.data.confirm_password.clone())
                                    };
                                    password_match_error.set(None);
                                    if password != confirm_password {
                                        password_match_error.set(Some("Passwords do not match".to_string()));
                                        return;
                                    }
                                    let token = reset_token();
                                    if token.is_empty() {
                                        // No reset_token means the verify step never completed
                                        // (e.g. state was wiped). Send the user back to start.
                                        password_match_error.set(Some("Session expired. Please start over.".to_string()));
                                        step.set(ForgotStep::RequestCode);
                                        return;
                                    }
                                    spawn(async move {
                                        password_reset
                                            .reset_password(ResetPasswordPayload {
                                                reset_token: token,
                                                password,
                                                confirm_password,
                                            })
                                            .await;
                                        if password_reset.reset.read().is_success() {
                                            // Clear state so a future visit starts fresh.
                                            password_reset.reset();
                                            reset_token.set(String::new());
                                            nav.replace(Route::LoginScreen {});
                                        }
                                    });
                                },
                                if reset_frame.is_loading() {
                                    div { class: "loading loading-spinner loading-xs" }
                                }
                                span { "Reset password" }
                            }
                        }
                    }

                    p { class: "text-sm text-center text-zinc-600 dark:text-zinc-400 mt-4 transition-colors duration-300",
                        "Remembered it? "
                        Link {
                            to: Route::LoginScreen {},
                            class: "text-zinc-700 dark:text-zinc-300 font-semibold hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors duration-150",
                            "Back to login"
                        }
                    }
                }
            }
        }
    }
}
