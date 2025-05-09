use sea_orm::{entity::prelude::*, Order, QueryOrder, Set, TransactionTrait};
use tokio::task;
use crate::{db::sea_models::email_verification, error::{DbResult, ErrorCode, ErrorResponse}};

use super::*;

impl Entity {
    pub const PER_PAGE: u64 = 20;

    // Create a new user
    pub async fn create(conn: &DbConn, new_user: NewUser) -> DbResult<Model> {
        let now = chrono::Utc::now().fixed_offset();
        let hash = task::spawn_blocking(move || password_auth::generate_hash(new_user.password))
            .await
            .map_err(|_| ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Failed to generate password hash"))?;

        let user = ActiveModel {
            name: Set(new_user.name),
            email: Set(new_user.email),
            password: Set(hash),
            role: Set(new_user.role),
            is_verified: Set(false),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };
        // create a transaction
        let transaction = conn.begin().await.map_err(|_| {
            ErrorResponse::new(ErrorCode::TransactionError)
                .with_message("Failed to begin transaction")
        })?;
        match user.insert(&transaction).await {
            Ok(model) => {
                email_verification::Entity::create(&transaction, model.id).await?;
                transaction.commit().await.map_err(|_| {
                    ErrorResponse::new(ErrorCode::TransactionError)
                        .with_message("Failed to commit transaction")
                })?;
                Ok(model)
            },
            Err(err) => {
                transaction.rollback().await.map_err(|_| {
                    ErrorResponse::new(ErrorCode::TransactionError)
                        .with_message("Failed to rollback transaction")
                })?;
                Err(err.into())
            },
        }
    }

    // Update an existing user
    pub async fn update(
        conn: &DbConn,
        user_id: i32,
        update_user: UpdateUser,
    ) -> DbResult<Option<Model>> {
        // Find the user by ID
        let user: Option<Model> = match Self::find_by_id(user_id).one(conn).await {
            Ok(user) => user,
            Err(err) => return Err(err.into()),
        };

        if let Some(user_model) = user {
            let mut user_active: ActiveModel = user_model.into();

            if let Some(name) = update_user.name {
                user_active.name = Set(name);
            }

            if let Some(email) = update_user.email {
                user_active.email = Set(email);
            }

            user_active.updated_at = Set(update_user.updated_at);

            match user_active.update(conn).await {
                Ok(updated_user) => Ok(Some(updated_user)),
                Err(err) => Err(err.into()),
            }
        } else {
            Ok(None)
        }
    }

    // Verify a user
    pub async fn verify(conn: &DbConn, user_id: i32) -> DbResult<Model> {
        let user = Self::find_by_id_with_404(conn, user_id).await?;
        let mut user_active: ActiveModel = user.into();
        
        user_active.is_verified = Set(true);
        user_active.updated_at = Set(chrono::Utc::now().fixed_offset());

        match user_active.update(conn).await {
            Ok(model) => Ok(model),
            Err(err) => Err(err.into()),
        }
    }

    // Change user password
    pub async fn change_password<T: ConnectionTrait>(
        conn: &T,
        user_id: i32,
        new_password: String,
    ) -> DbResult<()> {
        let user = Self::find_by_id_with_404(conn, user_id).await?;
        let mut user_active: ActiveModel = user.into();
        
        let hash = task::spawn_blocking(move || password_auth::generate_hash(new_password))
            .await
            .map_err(|_| ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Failed to generate password hash"))?;
        
        user_active.password = Set(hash);
        user_active.updated_at = Set(chrono::Utc::now().fixed_offset());

        match user_active.update(conn).await {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    // Find user by ID
    pub async fn get_by_id(conn: &DbConn, user_id: i32) -> DbResult<Option<Model>> {
        match Self::find_by_id(user_id).one(conn).await {
            Ok(model) => Ok(model),
            Err(err) => Err(err.into()),
        }
    }
    
    // Find user by ID with not found handling
    pub async fn find_by_id_with_404<T: ConnectionTrait>(conn: &T, user_id: i32) -> DbResult<Model> {
        match Self::find_by_id(user_id).one(conn).await {
            Ok(Some(model)) => Ok(model),
            Ok(None) => Err(ErrorResponse::new(ErrorCode::RecordNotFound)
                          .with_message(&format!("User with ID {} not found", user_id))),
            Err(err) => Err(err.into()),
        }
    }

    // Find user by email
    pub async fn find_by_email(conn: &DbConn, user_email: String) -> DbResult<Option<Model>> {
        match Self::find()
            .filter(Column::Email.eq(user_email))
            .one(conn)
            .await
        {
            Ok(model) => Ok(model),
            Err(err) => Err(err.into()),
        }
    }
    
    // Find user by email and forgot password code
    pub async fn find_by_email_and_forgot_password(
        conn: &DbConn, 
        user_email: String, 
        otp_code: String
    ) -> DbResult<Option<(Model, super::super::forgot_password::Model)>> {
        use sea_orm::{entity::*, query::*};
        use super::super::forgot_password::{Entity as ForgotPassword, Column as ForgotPasswordColumn};
        
        let result = Entity::find()
            .filter(Column::Email.eq(user_email))
            .join(JoinType::InnerJoin, Relation::ForgotPassword.def())
            .filter(ForgotPasswordColumn::Code.eq(otp_code))
            .find_with_related(ForgotPassword)
            .all(conn)
            .await;
            
        match result {
            Ok(mut results) => {
                if results.is_empty() {
                    return Ok(None);
                }
                
                let (user, mut forgot_passwords) = results.remove(0);
                let forgot_password = forgot_passwords.pop().unwrap();
                
                Ok(Some((user, forgot_password)))
            },
            Err(err) => Err(err.into()),
        }
    }

    // Admin operations

    // Admin create user
    pub async fn admin_create(conn: &DbConn, new_user: AdminCreateUser) -> DbResult<Model> {
        let now = chrono::Utc::now().fixed_offset();
        let hash = task::spawn_blocking(move || password_auth::generate_hash(new_user.password))
            .await
            .map_err(|_| ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Failed to generate password hash"))?;

        let user = ActiveModel {
            name: Set(new_user.name),
            email: Set(new_user.email),
            password: Set(hash),
            role: Set(new_user.role),
            avatar: Set(new_user.avatar),
            is_verified: Set(new_user.is_verified.unwrap_or(false)),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        match user.insert(conn).await {
            Ok(model) => Ok(model),
            Err(err) => Err(err.into()),
        }
    }

    // Admin update user
    pub async fn admin_update(
        conn: &DbConn,
        user_id: i32,
        update_user: AdminUpdateUser,
    ) -> DbResult<Option<Model>> {
        let user: Option<Model> = Self::get_by_id(conn, user_id).await?;

        if let Some(user_model) = user {
            let mut user_active: ActiveModel = user_model.into();

            if let Some(name) = update_user.name {
                user_active.name = Set(name);
            }

            if let Some(email) = update_user.email {
                user_active.email = Set(email);
            }

            if let Some(password) = update_user.password {
                let hash = task::spawn_blocking(move || password_auth::generate_hash(password))
                    .await
                    .map_err(|_| ErrorResponse::new(ErrorCode::InternalServerError)
                        .with_message("Failed to generate password hash"))?;
                user_active.password = Set(hash);
            }

            if let Some(role) = update_user.role {
                user_active.role = Set(role);
            }

            if let Some(avatar) = update_user.avatar {
                user_active.avatar = Set(Some(avatar));
            }

            if let Some(is_verified) = update_user.is_verified {
                user_active.is_verified = Set(is_verified);
            }

            user_active.updated_at = Set(update_user.updated_at);

            match user_active.update(conn).await {
                Ok(updated_user) => Ok(Some(updated_user)),
                Err(err) => Err(err.into()),
            }
        } else {
            Ok(None)
        }
    }

    // Admin delete user
    pub async fn admin_delete(conn: &DbConn, user_id: i32) -> DbResult<u64> {
        match Self::delete_by_id(user_id).exec(conn).await {
            Ok(result) => Ok(result.rows_affected),
            Err(err) => Err(err.into()),
        }
    }

    // Find users with query parameters for admin
    pub async fn admin_list(
        conn: &DbConn,
        query: AdminUserQuery,
    ) -> DbResult<(Vec<Model>, u64)> {
        let mut user_query = Self::find();

        // Apply filters
        if let Some(email_filter) = query.email {
            let email_pattern = format!("%{}%", email_filter);
            user_query = user_query.filter(Column::Email.contains(&email_pattern));
        }

        if let Some(name_filter) = query.name {
            let name_pattern = format!("%{}%", name_filter);
            user_query = user_query.filter(Column::Name.contains(&name_pattern));
        }

        if let Some(role_filter) = query.role {
            user_query = user_query.filter(Column::Role.eq(role_filter));
        }

        if let Some(status_filter) = query.status {
            user_query = user_query.filter(Column::IsVerified.eq(status_filter));
        }

        if let Some(created_at_filter) = query.created_at {
            user_query = user_query.filter(Column::CreatedAt.eq(created_at_filter));
        }

        if let Some(updated_at_filter) = query.updated_at {
            user_query = user_query.filter(Column::UpdatedAt.eq(updated_at_filter));
        }

        // Handle sort_by fields
        if let Some(sort_fields) = &query.sort_by {
            for field in sort_fields {
                let order = if query.sort_order.as_deref() == Some("asc") {
                    Order::Asc
                } else {
                    Order::Desc
                };
                
                user_query = match field.as_str() {
                    "email" => user_query.order_by(Column::Email, order),
                    "name" => user_query.order_by(Column::Name, order),
                    "role" => user_query.order_by(Column::Role, order),
                    "status" => user_query.order_by(Column::IsVerified, order),
                    "created_at" => user_query.order_by(Column::CreatedAt, order),
                    "updated_at" => user_query.order_by(Column::UpdatedAt, order),
                    _ => user_query,
                };
            }
        } else {
            // Default ordering
            let order = if query.sort_order.as_deref() == Some("asc") {
                Order::Asc
            } else {
                Order::Desc
            };
            user_query = user_query.order_by(Column::Id, order);
        }

        // Handle pagination
        let page = match query.page_no {
            Some(p) if p > 0 => p,
            _ => 1,
        };
        
        let paginator = user_query.paginate(conn, Self::PER_PAGE);
        
        // Get total count and paginated results
        match paginator.num_items().await {
            Ok(total) => match paginator.fetch_page(page - 1).await {
                Ok(results) => Ok((results, total)),
                Err(err) => Err(err.into()),
            },
            Err(err) => Err(err.into()),
        }
    }
}