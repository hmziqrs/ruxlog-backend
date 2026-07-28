use sea_orm_migration::prelude::*;

/// Create `email_suppression`: the recipient blacklist enforced before every
/// outbound send.
///
/// - unique `recipient` so re-bounces upsert instead of duplicating (and so the
///   send-path lookup is a single index hit)
/// - index on `reason` for filtered admin listings
/// - `permanent` + `last_seen` drive enforcement: a permanent row, or a
///   non-permanent `bounce` row whose `last_seen` is within the soft-bounce
///   cooldown, suppresses delivery
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(EmailSuppression::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(EmailSuppression::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(EmailSuppression::Recipient)
                            .string_len(320)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(EmailSuppression::Reason)
                            .text()
                            .not_null()
                            .default("bounce"),
                    )
                    .col(ColumnDef::new(EmailSuppression::Source).text().null())
                    .col(ColumnDef::new(EmailSuppression::Diagnostic).text().null())
                    .col(
                        ColumnDef::new(EmailSuppression::Permanent)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .col(
                        ColumnDef::new(EmailSuppression::LastSeen)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(EmailSuppression::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(EmailSuppression::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_email_suppression_recipient")
                    .table(EmailSuppression::Table)
                    .col(EmailSuppression::Recipient)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_email_suppression_reason")
                    .table(EmailSuppression::Table)
                    .col(EmailSuppression::Reason)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(EmailSuppression::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum EmailSuppression {
    Table,
    Id,
    Recipient,
    Reason,
    Source,
    Diagnostic,
    Permanent,
    LastSeen,
    CreatedAt,
    UpdatedAt,
}
