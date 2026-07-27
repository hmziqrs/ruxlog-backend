use sea_orm_migration::prelude::*;

/// Create `notifications`: the per-user in-app inbox. `data` is an optional
/// JSON blob of arbitrary payload (e.g. the post id that triggered the
/// notification); `read_at` is NULL until the user marks it read.
///
/// Composite index on `(user_id, created_at)` serves the newest-first paginated
/// inbox listing. (Postgres b-tree indexes are bidirectional, so the same index
/// serves `ORDER BY created_at DESC`.)
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Notifications::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Notifications::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Notifications::UserId).integer().not_null())
                    .col(ColumnDef::new(Notifications::Kind).text().not_null())
                    .col(ColumnDef::new(Notifications::Title).text().not_null())
                    .col(ColumnDef::new(Notifications::Body).text().not_null())
                    .col(ColumnDef::new(Notifications::Data).json_binary())
                    .col(ColumnDef::new(Notifications::ReadAt).timestamp_with_time_zone())
                    .col(
                        ColumnDef::new(Notifications::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_notifications_user_id")
                            .from(Notifications::Table, Notifications::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_notifications_user_id_created_at")
                    .table(Notifications::Table)
                    .col(Notifications::UserId)
                    .col(Notifications::CreatedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Notifications::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum Notifications {
    Table,
    Id,
    UserId,
    Kind,
    Title,
    Body,
    Data,
    ReadAt,
    CreatedAt,
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
}
