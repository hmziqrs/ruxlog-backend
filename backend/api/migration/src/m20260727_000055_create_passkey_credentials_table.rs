use sea_orm_migration::prelude::*;

/// Issue #4 (passkey/WebAuthn): stores registered passkey (WebAuthn)
/// credentials per user. TOTP 2FA was already implemented; this adds the
/// WebAuthn device factor.
///
/// Schema (per charter):
///   passkey_credentials(
///     id, user_id FK->users,
///     credential_id TEXT UNIQUE,   -- base64url credential id (opaque lookup key)
///     public_key   BYTEA,          -- serialized webauthn_rs::Passkey (serde_json bytes)
///     counter      BIGINT NOT NULL DEFAULT 0,  -- authenticator signature counter (clone detection)
///     device_type  TEXT NULL,      -- optional client-supplied label
///     transports   JSONB NULL,     -- client-supplied transports array
///     created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
///     last_used_at TIMESTAMPTZ NULL
///   )
/// Index on `user_id`; unique on `credential_id`.
///
/// The full `webauthn_rs::prelude::Passkey` (COSE public key + counter +
/// cred id + user-verified flag) is serialized via its serde impl into
/// `public_key`, so the credential can be reconstructed for authentication.
/// The standalone `counter` column mirrors `Passkey.counter` and is the
/// authoritative "highest seen signature counter" used for clone detection
/// (a second assertion whose counter <= the stored one is rejected).
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(PasskeyCredentials::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PasskeyCredentials::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::UserId)
                            .integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::CredentialId)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::PublicKey)
                            .binary()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::Counter)
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .col(ColumnDef::new(PasskeyCredentials::DeviceType).text().null())
                    .col(
                        ColumnDef::new(PasskeyCredentials::Transports)
                            .json_binary()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(PasskeyCredentials::LastUsedAt)
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_passkey_credentials_user_id")
                            .from(PasskeyCredentials::Table, PasskeyCredentials::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_passkey_credentials_credential_id")
                    .table(PasskeyCredentials::Table)
                    .col(PasskeyCredentials::CredentialId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_passkey_credentials_user_id")
                    .table(PasskeyCredentials::Table)
                    .col(PasskeyCredentials::UserId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PasskeyCredentials::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum PasskeyCredentials {
    Table,
    Id,
    UserId,
    CredentialId,
    PublicKey,
    Counter,
    DeviceType,
    Transports,
    CreatedAt,
    LastUsedAt,
}

#[derive(Iden)]
enum Users {
    Table,
    Id,
}
