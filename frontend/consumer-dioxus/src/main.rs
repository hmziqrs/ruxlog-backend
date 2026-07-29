use dioxus::{logger::tracing, prelude::*};

use crate::components::AmbientCanvasBackground;
use oxui::components::SonnerToaster;

pub mod components;
mod config;
pub mod containers;
pub mod env;
pub mod hooks;
pub mod router;
pub mod screens;
pub mod seo;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
mod csp_nonce;
pub mod server_fns;
pub mod utils;

#[cfg(feature = "analytics")]
pub mod analytics;

// WebAuthn / passkey browser glue (issue #4). Referenced by the consumer
// login + profile screens, so gated under the auth feature that gates those.
#[cfg(feature = "consumer-auth")]
pub mod passkey;

fn configure_http_client() {
    // Configure HTTP client base URL only. The per-session CSRF token is no
    // longer baked in at build time (plan Phase 5); it is fetched from
    // `/csrf/v1/generate` on boot (see App) and after login.
    println!("APP_API_URL: {}", env::APP_API_URL);

    let base_url = if env::APP_API_URL.starts_with("http") {
        env::APP_API_URL.to_string()
    } else {
        format!("http://{}", env::APP_API_URL)
    };
    oxcore::http::configure(base_url);
}

#[cfg(feature = "server")]
fn main() {
    configure_http_client();

    // Build the Dioxus fullstack router ourselves so we can wrap it in the CSP
    // nonce layer (`csp_nonce`). Dioxus 0.8 fullstack SSR injects a dynamic
    // per-render hydration `<script>` into the document that a static CSP
    // cannot authorize: it is un-hashable, and granting 'unsafe-inline' would
    // re-enable stored-XSS via `dangerous_inner_html`. The nonce layer stamps
    // ONLY the Dioxus hydration scripts with a per-request nonce and serves
    // `script-src 'self' 'nonce-<v>' 'wasm-unsafe-eval' 'unsafe-eval'`. See
    // `csp_nonce.rs` for the rationale and the safety-critical invariant.
    dioxus::server::serve(|| async {
        Ok(dioxus::server::router(App)
            .layer(axum::middleware::from_fn(csp_nonce::csp_nonce_middleware)))
    });
}

#[cfg(all(
    feature = "web",
    not(any(feature = "server", feature = "desktop", feature = "mobile"))
))]
fn main() {
    configure_http_client();

    dioxus::LaunchBuilder::new()
        .with_cfg(web! {
            dioxus::web::Config::default()
        })
        .launch(App);
}

// Desktop, mobile, or any other non-server/non-web build (dx builds native
// clients without enabling the desktop/mobile Cargo features)
#[cfg(not(any(feature = "server", feature = "web")))]
fn main() {
    run_client();
}

#[cfg(all(target_os = "android", not(any(feature = "server", feature = "web"))))]
#[no_mangle]
fn android_main(app: android_activity::AndroidApp) {
    // dioxus-native (used by `--renderer native`) needs the Android app handle
    // registered before creating its winit event loop.
    blitz_shell::set_android_app(app);
    run_client();
}

#[cfg(not(any(feature = "server", feature = "web")))]
fn run_client() {
    configure_http_client();
    dioxus::launch(App);
}

const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

#[component]
fn App() -> Element {
    tracing::info!("APP_API_URL: {}", env::APP_API_URL);

    // Initialize Firebase Analytics (WASM-only)
    #[cfg(all(target_arch = "wasm32", feature = "analytics"))]
    use_effect(|| {
        if analytics::initialize() {
            tracing::info!("Firebase Analytics enabled");
        } else {
            tracing::warn!("Firebase Analytics initialization failed - check configuration");
        }
    });

    // Fetch the per-session CSRF token on boot (client builds only). The backend
    // bootstraps/rehydrates the session and returns the bound token, which is
    // then attached to every mutating request. Login re-fetches it too.
    #[cfg(not(feature = "server"))]
    use_effect(|| {
        spawn(async move {
            if let Err(e) = oxcore::http::refresh_csrf_token().await {
                tracing::warn!("Failed to refresh CSRF token on boot: {e}");
            }
        });
    });

    // Initialize document theme from persistent storage on app mount (WASM-only)
    // Defaults to dark mode when no preference is stored
    #[cfg(target_arch = "wasm32")]
    use_effect(|| {
        let stored = utils::persist::get_theme();
        spawn(async move {
            match stored.as_deref() {
                Some("light") => {
                    let _ =
                        document::eval("document.documentElement.classList.remove('dark');").await;
                }
                _ => {
                    // Default to dark mode for "dark", None, or any other value
                    let _ = document::eval("document.documentElement.classList.add('dark');").await;
                }
            }
        });
    });

    rsx! {
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        document::Link { rel: "preconnect", href: "https://fonts.googleapis.com" }
        document::Link {
            rel: "preconnect",
            href: "https://fonts.gstatic.com",
            "crossorigin": "",
        }
        document::Link {
            rel: "stylesheet",
            href: "https://fonts.googleapis.com/css2?family=Geist+Mono:wght@400..600&family=Geist:wght@400..600&display=swap",
        }
        AmbientCanvasBackground {}
        div { style: "position: relative; z-index: 10;",
            SuspenseBoundary {
                fallback: |_| rsx! {
                    div { class: "min-h-screen flex items-center justify-center",
                        div { class: "animate-pulse text-muted-foreground", "Loading..." }
                    }
                },
                SonnerToaster { Router::<crate::router::Route> {} }
            }
        }
    }
}
