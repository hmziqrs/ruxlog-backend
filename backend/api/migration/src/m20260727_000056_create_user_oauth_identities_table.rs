use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum UserOauthIdentities {
    Table,
    Id,
    UserId,
    Provider,
    ProviderUserId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create user_oauth_identities table.
        //
        // One user may have several linked third-party identities (Facebook,
        // GitHub, Apple, ...), and one provider identity belongs to exactly one
        // user. The (provider, provider_user_id) pair is globally unique so a
        // single provider account can never be linked to two local users.
        manager
            .create_table(
                Table::create()
                    .table(UserOauthIdentities::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(UserOauthIdentities::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(UserOauthIdentities::UserId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserOauthIdentities::Provider)
                            .string_len(32) // "facebook" | "github" | "apple" | ...
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserOauthIdentities::ProviderUserId)
                            .string_len(255) // opaque, provider-scoped subject id
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(UserOauthIdentities::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_user_oauth_identities_user_id")
                            .from(UserOauthIdentities::Table, UserOauthIdentities::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Globally unique link: one provider account → one local user.
        manager
            .create_index(
                Index::create()
                    .name("uq_user_oauth_identities_provider_provider_user_id")
                    .table(UserOauthIdentities::Table)
                    .col(UserOauthIdentities::Provider)
                    .col(UserOauthIdentities::ProviderUserId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Look up a user's linked providers / a user's identities.
        manager
            .create_index(
                Index::create()
                    .name("idx_user_oauth_identities_user_id")
                    .table(UserOauthIdentities::Table)
                    .col(UserOauthIdentities::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(UserOauthIdentities::Table).to_owned())
            .await
    }
}
