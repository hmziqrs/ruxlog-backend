pub mod controller;
pub mod validator;

#[cfg(feature = "post-management")]
use crate::config;
use crate::{middlewares::auth_guard, AppState};
#[cfg(feature = "post-management")]
use axum::extract::DefaultBodyLimit;
use axum::{middleware, routing::post, Router};

pub fn routes() -> Router<AppState> {
    // The author-only `protected` sub-router always carries the read/query,
    // revision, schedule and series routes. The write routes (create / update /
    // autosave / delete) are gated by the `post-management` feature so an
    // operator can produce a stripped build (`--no-default-features
    // --features <subset>`) that disables post CRUD while keeping reads alive.
    // `post-management` is included in both `basic` and `full`, so a default
    // `cargo build` keeps all current write behavior.
    #[cfg_attr(not(feature = "post-management"), allow(unused_mut))]
    let mut protected = Router::<AppState>::new()
        .route("/query", post(controller::query))
        .route(
            "/revisions/{post_id}/list",
            post(controller::revisions_list),
        )
        .route(
            "/revisions/{post_id}/restore/{revision_id}",
            post(controller::revisions_restore),
        )
        .route("/schedule", post(controller::schedule))
        .route("/series/create", post(controller::series_create))
        .route(
            "/series/update/{series_id}",
            post(controller::series_update),
        )
        .route(
            "/series/delete/{series_id}",
            post(controller::series_delete),
        )
        .route("/series/list", post(controller::series_list))
        .route(
            "/series/add/{post_id}/{series_id}",
            post(controller::series_add),
        )
        .route(
            "/series/remove/{post_id}/{series_id}",
            post(controller::series_remove),
        );

    #[cfg(feature = "post-management")]
    {
        // Author-facing write paths with the larger body limit for post bodies.
        let post_limited = Router::<AppState>::new()
            .route("/create", post(controller::create))
            .route("/update/{post_id}", post(controller::update))
            .route("/autosave", post(controller::autosave))
            .layer(DefaultBodyLimit::max(config::body_limits::POST));

        protected = protected
            .route("/delete/{post_id}", post(controller::delete))
            .merge(post_limited);
    }

    let protected = protected.route_layer(middleware::from_fn(
        auth_guard::verified_with_role::<{ auth_guard::ROLE_AUTHOR }>,
    ));

    // Routes requiring authentication (any logged-in user)
    let authenticated = Router::<AppState>::new()
        .route("/like/{post_id}", post(controller::like_post))
        .route("/unlike/{post_id}", post(controller::unlike_post))
        .route("/like/status/{post_id}", post(controller::like_status))
        .route("/like/status/batch", post(controller::like_status_batch))
        .route_layer(middleware::from_fn(auth_guard::authenticated));

    let public = Router::<AppState>::new()
        .route("/view/{id_or_slug}", post(controller::find_by_id_or_slug))
        .route("/list/published", post(controller::find_published_posts))
        .route("/sitemap", post(controller::sitemap))
        .route("/track_view/{post_id}", post(controller::track_view));

    protected.merge(authenticated).merge(public)
}
