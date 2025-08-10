use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use crate::db::sea_models::post::UpdatePost;
use crate::db::sea_models::{post_revision, post_series, post_series_post, scheduled_post};
use axum_macros::debug_handler;
use sea_orm::EntityTrait;
use serde_json::json;

use crate::db::sea_models::user::UserRole;
use crate::{
    db::sea_models::post,
    error::{ErrorCode, ErrorResponse},
    extractors::ValidatedJson,
    modules::post_v1::validator::V1UpdatePostPayload,
    services::auth::AuthSession,
    AppState,
};

use super::validator::{
    V1AutosavePayload, V1CreatePostPayload, V1PostQueryParams, V1SchedulePayload,
    V1SeriesCreatePayload, V1SeriesListQuery, V1SeriesUpdatePayload,
};

#[debug_handler]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1CreatePostPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap();
    let new_post = payload.0.into_new_post(user.id);

    match post::Entity::create(&state.sea_db, new_post).await {
        Ok(post) => Ok((StatusCode::CREATED, Json(json!(post)))),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn find_by_id_or_slug(
    State(state): State<AppState>,
    Path(slug_or_id): Path<String>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let query = match slug_or_id.parse::<i32>() {
        Ok(id) => post::Entity::find_by_id_or_slug(&state.sea_db, Some(id), None).await,
        Err(_) => post::Entity::find_by_id_or_slug(&state.sea_db, None, Some(slug_or_id)).await,
    };

    match query {
        Ok(Some(post)) => Ok((StatusCode::OK, Json(json!(post)))),
        Ok(None) => {
            Err(ErrorResponse::new(ErrorCode::RecordNotFound).with_message("Post not found"))
        }
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn update(
    State(state): State<AppState>,
    Path(post_id): Path<i32>,
    payload: ValidatedJson<V1UpdatePostPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let update_post = payload.0.into_update_post();

    match post::Entity::update(&state.sea_db, post_id, update_post).await {
        Ok(Some(post)) => Ok((StatusCode::OK, Json(json!(post)))),
        Ok(None) => {
            Err(ErrorResponse::new(ErrorCode::RecordNotFound).with_message("Post does not exist"))
        }
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn delete(
    State(state): State<AppState>,
    Path(post_id): Path<i32>,
) -> Result<impl IntoResponse, ErrorResponse> {
    match post::Entity::delete(&state.sea_db, post_id).await {
        Ok(1) => Ok((
            StatusCode::OK,
            Json(json!({ "message": "Post deleted successfully" })),
        )),
        Ok(0) => {
            Err(ErrorResponse::new(ErrorCode::RecordNotFound).with_message("Post does not exist"))
        }
        Ok(_) => Err(ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Internal server error occurred while deleting post")),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn find_published_posts(
    State(state): State<AppState>,
    payload: ValidatedJson<V1PostQueryParams>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let page = payload.page.clone().unwrap_or(1);
    match post::Entity::find_published_paginated(&state.sea_db, payload.0.into_post_query()).await {
        Ok((posts, total)) => Ok((
            StatusCode::OK,
            Json(json!({
                "data": posts,
                "total": total,
                "per_page": post::Entity::PER_PAGE as u64,
                "page": page,
            })),
        )),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn track_view(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(post_id): Path<i32>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user_id: Option<i32> = auth.user.map(|user| user.id);
    match post::Entity::increment_view_count(&state.sea_db, post_id, user_id, None, None).await {
        Ok(_) => Ok((
            StatusCode::OK,
            Json(json!({ "message": "View tracked successfully" })),
        )),
        Err(err) => Err(ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Failed to track view")
            .with_details(err.to_string())),
    }
}

#[debug_handler]
pub async fn sitemap(State(state): State<AppState>) -> Result<impl IntoResponse, ErrorResponse> {
    match post::Entity::sitemap(&state.sea_db).await {
        Ok(posts) => Ok((StatusCode::OK, Json(posts))),
        Err(err) => Err(ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Failed to fetch posts")
            .with_details(err.to_string())),
    }
}

#[debug_handler]
pub async fn query(
    State(state): State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1PostQueryParams>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap();
    let mut query_params = payload.0.clone();

    // Role-based access control
    match user.role {
        UserRole::Author => {
            query_params.author_id = Some(user.id);
        }
        UserRole::Admin | UserRole::SuperAdmin => {}
        UserRole::Moderator => {
            // Moderators can view all posts for moderation purposes
            // No modification needed
        }
        UserRole::User => {
            return Err(
                ErrorResponse::new(ErrorCode::OperationNotAllowed).with_message("Access denied")
            );
        }
    }

    let page = query_params.page.clone().unwrap_or(1);

    match post::Entity::search(&state.sea_db, query_params.into_post_query()).await {
        Ok((posts, total)) => Ok((
            StatusCode::OK,
            Json(json!({
                "data": posts,
                "total": total,
                "per_page": post::Entity::PER_PAGE,
                "page": page,
            })),
        )),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn autosave(
    State(state): State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1AutosavePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();
    let p = payload.0;

    match post_revision::Entity::create(&state.sea_db, p.post_id, p.content.clone(), None).await {
        Ok(revision) => {
            let update = UpdatePost {
                title: None,
                slug: None,
                content: Some(p.content),
                excerpt: None,
                featured_image: None,
                status: None,
                published_at: None,
                updated_at: p.updated_at,
                category_id: None,
                view_count: None,
                likes_count: None,
                tag_ids: None,
            };

            match post::Entity::update(&state.sea_db, p.post_id, update).await {
                Ok(_) => Ok((StatusCode::OK, Json(json!(revision)))),
                Err(err) => Err(err.into()),
            }
        }
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn revisions_list(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(post_id): Path<i32>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();
    let page: u64 = 1;

    match post_revision::Entity::list_by_post(&state.sea_db, post_id, Some(page), None).await {
        Ok((items, total)) => Ok((
            StatusCode::OK,
            Json(json!({ "data": items, "total": total, "page": page })),
        )),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn revisions_restore(
    State(state): State<AppState>,
    auth: AuthSession,
    Path((post_id, revision_id)): Path<(i32, i32)>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();

    let rev_opt = match post_revision::Entity::find_by_id(revision_id)
        .one(&state.sea_db)
        .await
    {
        Ok(r) => r,
        Err(err) => return Err(err.into()),
    };

    let rev = if let Some(r) = rev_opt {
        r
    } else {
        return Err(
            ErrorResponse::new(ErrorCode::RecordNotFound).with_message("Revision not found")
        );
    };

    if rev.post_id != post_id {
        return Err(ErrorResponse::new(ErrorCode::OperationNotAllowed)
            .with_message("Revision does not belong to the specified post"));
    }

    let now = chrono::Utc::now().fixed_offset();
    let update = UpdatePost {
        title: None,
        slug: None,
        content: Some(rev.content.clone()),
        excerpt: None,
        featured_image: None,
        status: None,
        published_at: None,
        updated_at: now,
        category_id: None,
        view_count: None,
        likes_count: None,
        tag_ids: None,
    };

    match post::Entity::update(&state.sea_db, post_id, update).await {
        Ok(_) => {
            let meta = serde_json::json!({ "restored_from_revision_id": revision_id });
            match post_revision::Entity::create(
                &state.sea_db,
                post_id,
                rev.content.clone(),
                Some(meta),
            )
            .await
            {
                Ok(new_rev) => Ok((StatusCode::OK, Json(json!(new_rev)))),
                Err(err) => Err(err.into()),
            }
        }
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn schedule(
    State(state): State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1SchedulePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();
    let p = payload.0;

    match scheduled_post::Entity::upsert(&state.sea_db, p.post_id, p.publish_at).await {
        Ok(model) => Ok((StatusCode::OK, Json(json!(model)))),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn series_create(
    State(state): State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1SeriesCreatePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();
    let p = payload.0;

    match post_series::Entity::create(&state.sea_db, p.name, p.slug, p.description).await {
        Ok(series) => Ok((StatusCode::CREATED, Json(json!(series)))),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn series_update(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(series_id): Path<i32>,
    payload: ValidatedJson<V1SeriesUpdatePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();

    match post_series::Entity::update(
        &state.sea_db,
        series_id,
        payload.0.name,
        payload.0.slug,
        payload.0.description,
    )
    .await
    {
        Ok(Some(series)) => Ok((StatusCode::OK, Json(json!(series)))),
        Ok(None) => {
            Err(ErrorResponse::new(ErrorCode::RecordNotFound).with_message("Series not found"))
        }
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn series_delete(
    State(state): State<AppState>,
    auth: AuthSession,
    Path(series_id): Path<i32>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();

    match post_series::Entity::delete(&state.sea_db, series_id).await {
        Ok(1) => Ok((
            StatusCode::OK,
            Json(json!({ "message": "Deleted successfully" })),
        )),
        Ok(0) => {
            Err(ErrorResponse::new(ErrorCode::RecordNotFound).with_message("Series not found"))
        }
        Ok(_) => Err(ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Internal server error occurred while deleting series")),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn series_list(
    State(state): State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1SeriesListQuery>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();
    let page = payload.page.clone().unwrap_or(1);

    match post_series::Entity::list(&state.sea_db, payload.page, None, payload.search.clone()).await
    {
        Ok((items, total)) => {
            let mut data = Vec::with_capacity(items.len());
            for s in items {
                let count = post_series_post::Entity::count_by_series(&state.sea_db, s.id)
                    .await
                    .unwrap_or(0);
                data.push(serde_json::json!({
                    "id": s.id,
                    "name": s.name,
                    "slug": s.slug,
                    "description": s.description,
                    "created_at": s.created_at,
                    "updated_at": s.updated_at,
                    "posts_count": count as i64,
                }));
            }

            Ok((
                StatusCode::OK,
                Json(json!({ "data": data, "total": total, "page": page })),
            ))
        }
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn series_add(
    State(state): State<AppState>,
    auth: AuthSession,
    Path((post_id, series_id)): Path<(i32, i32)>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();

    let payload = post_series_post::NewPostSeriesPost {
        series_id,
        post_id,
        sort_order: None,
    };

    match post_series_post::Entity::add(&state.sea_db, payload).await {
        Ok(model) => Ok((StatusCode::CREATED, Json(json!(model)))),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn series_remove(
    State(state): State<AppState>,
    auth: AuthSession,
    Path((post_id, series_id)): Path<(i32, i32)>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _user = auth.user.unwrap();

    let payload = post_series_post::RemovePostSeriesPost { series_id, post_id };

    match post_series_post::Entity::remove(&state.sea_db, payload).await {
        Ok(affected) if affected > 0 => Ok((
            StatusCode::OK,
            Json(json!({ "message": "Removed successfully" })),
        )),
        Ok(_) => {
            Err(ErrorResponse::new(ErrorCode::RecordNotFound).with_message("Mapping not found"))
        }
        Err(err) => Err(err.into()),
    }
}
