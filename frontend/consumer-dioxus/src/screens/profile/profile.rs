use dioxus::prelude::*;
use hmziq_dioxus_free_icons::icons::ld_icons::{LdMail, LdUser};
use hmziq_dioxus_free_icons::Icon;
use oxui::shadcn::button::{Button, ButtonVariant};
use ruxlog_shared::store::passkey::RegisterFinishPayload;
use ruxlog_shared::{use_auth, use_passkey};

#[component]
pub fn ProfileScreen() -> Element {
    let auth_store = use_auth();
    let nav = use_navigator();
    let user = auth_store.user.read();
    let passkey_store = use_passkey();
    // Passkeys (WebAuthn, issue #4): list the user's registered credentials on
    // mount so the "Security keys" section reflects the real server state.
    use_effect(move || {
        let passkey_store = use_passkey();
        spawn(async move {
            passkey_store.list().await;
        });
    });

    if let Some(user) = &*user {
        rsx! {
            div { class: "min-h-screen",
                div { class: "container mx-auto px-4 py-12 max-w-4xl",
                    // Header
                    div { class: "mb-8",
                        h1 { class: "text-3xl font-bold mb-2", "Profile" }
                        p { "Manage your account settings and preferences" }
                    }

                    // Profile card
                    div { class: "bg-card border border-border rounded-lg shadow-lg overflow-hidden",
                        // Cover/Header section
                        div { class: "h-32 bg-gradient-to-r from-primary/20 via-primary/10 to-primary/20" }

                        div { class: "px-8 pb-8",
                            // Avatar and basic info
                            div { class: "-mt-16 mb-6",
                                div { class: "w-32 h-32 rounded-full bg-primary/20 border-4 border-card flex items-center justify-center",
                                    if let Some(avatar) = &user.avatar {
                                        img {
                                            src: "{avatar.file_url}",
                                            alt: "{user.name}",
                                            class: "w-full h-full rounded-full object-cover"
                                        }
                                    } else {
                                        span { class: "text-4xl font-bold",
                                            "{user.name.chars().next().unwrap_or('U').to_uppercase()}"
                                        }
                                    }
                                }
                            }

                            div { class: "space-y-6",
                                // Name
                                div { class: "flex items-start gap-4",
                                    div { class: "w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center shrink-0",
                                        Icon { icon: LdUser, class: "w-6 h-6" }
                                    }
                                    div { class: "flex-1",
                                        p { class: "text-sm mb-1", "Name" }
                                        p { class: "text-lg font-medium", "{user.name}" }
                                    }
                                }

                                // Email
                                div { class: "flex items-start gap-4",
                                    div { class: "w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center shrink-0",
                                        Icon { icon: LdMail, class: "w-6 h-6" }
                                    }
                                    div { class: "flex-1",
                                        p { class: "text-sm mb-1", "Email" }
                                        p { class: "text-lg font-medium", "{user.email}" }
                                        if user.is_verified {
                                            span { class: "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/10 mt-1",
                                                "✓ Verified"
                                            }
                                        } else {
                                            span { class: "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-500/10 mt-1",
                                                "⚠ Not verified"
                                            }
                                        }
                                    }
                                }

                                // Security keys / Passkeys (issue #4).
                                // Lists the user's registered WebAuthn credentials
                                // with register/remove actions that flow through the
                                // passkey store + browser WebAuthn helper.
                                div { class: "pt-6 border-t border-border",
                                    p { class: "text-sm mb-3 font-medium",
                                        "Security keys (Passkeys)"
                                    }
                                    if !crate::passkey::is_supported() {
                                        p { class: "text-xs text-muted-foreground mb-3",
                                            "Your browser does not support passkeys."
                                        }
                                    }
                                    div { class: "space-y-2 mb-3",
                                        for cred in passkey_store.list.read().data.clone().unwrap_or_default() {
                                            div {
                                                class: "flex items-center justify-between p-3 rounded-lg border border-border",
                                                p {
                                                    class: "font-medium text-sm",
                                                    { cred.device_type.clone().unwrap_or_else(|| "Passkey".to_string()) }
                                                }
                                                Button {
                                                    variant: ButtonVariant::Outline,
                                                    onclick: {
                                                        let cred_id = cred.credential_id.clone();
                                                        move |_| {
                                                            spawn(async move {
                                                                passkey_store.remove(cred_id).await;
                                                                passkey_store.list().await;
                                                            });
                                                        }
                                                    },
                                                    "Remove"
                                                }
                                            }
                                        }
                                    }
                                    Button {
                                        class: "mt-3",
                                        variant: ButtonVariant::Outline,
                                        disabled: passkey_store.register.read().is_loading()
                                            || !crate::passkey::is_supported(),
                                        onclick: move |_e: Event<MouseData>| {
                                            spawn(async move {
                                                if let Some(begin) =
                                                    passkey_store.register_begin().await
                                                {
                                                    match crate::passkey::create_credentials(
                                                        &begin.challenge,
                                                    )
                                                    .await
                                                    {
                                                        Ok(credential) => {
                                                            let registration_state =
                                                                begin.registration_state;
                                                            passkey_store
                                                                .register_finish(
                                                                    RegisterFinishPayload {
                                                                        credential,
                                                                        registration_state,
                                                                        device_type: Some(
                                                                            "WebAuthn".to_string(),
                                                                        ),
                                                                        transports: None,
                                                                    },
                                                                )
                                                                .await;
                                                            passkey_store.list().await;
                                                        }
                                                        Err(e) => {
                                                            dioxus::logger::tracing::error!(
                                                                "passkey registration failed: {e}"
                                                            );
                                                        }
                                                    }
                                                }
                                            });
                                        },
                                        if passkey_store.register.read().is_loading() {
                                            div { class: "loading loading-spinner loading-xs" }
                                        }
                                        span { "Add passkey" }
                                    }
                                }

                                // Actions
                                div { class: "pt-6 border-t border-border flex gap-3",
                                    Button {
                                        onclick: move |_| {
                                            nav.push(crate::router::Route::ProfileEditScreen {});
                                        },
                                        class: "flex-1",
                                        "Edit Profile"
                                    }
                                    Button {
                                        variant: ButtonVariant::Outline,
                                        onclick: move |_| {
                                            spawn(async move {
                                                auth_store.logout().await;
                                                nav.push(crate::router::Route::LoginScreen {});
                                            });
                                        },
                                        "Sign Out"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    } else {
        // Not logged in - redirect to login
        use_effect(move || {
            nav.push(crate::router::Route::LoginScreen {});
        });

        rsx! {
            div { class: "min-h-screen flex items-center justify-center",
                div { "Redirecting to login..." }
            }
        }
    }
}
