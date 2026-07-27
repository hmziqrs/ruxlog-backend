use sea_orm_migration::prelude::*;

/// Create `devices`: registered FCM push targets, one row per (user, token).
///
/// - unique (user_id, token) so a re-register upserts instead of duplicating
/// - index on `token` for prune-by-token lookups
/// - index on `user_id` for the fan-out "list this user's devices" query
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Devices::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Devices::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Devices::UserId).integer().not_null())
                    .col(ColumnDef::new(Devices::Token).text().not_null())
                    .col(ColumnDef::new(Devices::Platform).text().not_null())
                    .col(
                        ColumnDef::new(Devices::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Devices::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(Devices::LastSeenAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_devices_user_id")
                            .from(Devices::Table, Devices::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_devices_user_id_token")
                    .table(Devices::Table)
                    .col(Devices::UserId)
                    .col(Devices::Token)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_devices_token")
                    .table(Devices::Table)
                    .col(Devices::Token)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_devices_user_id")
                    .table(Devices::Table)
                    .col(Devices::UserId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Devices::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum Devices {
    Table,
    Id,
    UserId,
    Token,
    Platform,
    CreatedAt,
    UpdatedAt,
    LastSeenAt,
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
}
