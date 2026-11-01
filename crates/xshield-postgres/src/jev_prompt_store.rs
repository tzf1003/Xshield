//! Jev instruction versions (docs/07-console-architecture.md section 7.5.5).
//!
//! The gateway writes one row per distinct instruction text when it starts. A
//! Jev document refers to its row by id, so the full request sent to Jev can be
//! rebuilt even after the instructions changed.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};

/// The text of one instruction version.
#[derive(Debug, Clone, PartialEq)]
pub struct JevPrompt {
    /// Version id, `jq_` plus 16 hex digits.
    pub id: String,
    /// The two questions: instructions, criteria and choices, as sent.
    pub questions: serde_json::Value,
    /// When the gateway first registered this version.
    pub first_seen: DateTime<Utc>,
}

/// Fetches one instruction version.
///
/// # Errors
/// Returns [`sqlx::Error`] when the query fails.
pub async fn get(pool: &PgPool, id: &str) -> Result<Option<JevPrompt>, sqlx::Error> {
    let row = sqlx::query("SELECT id, questions, first_seen FROM jev_prompts WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    row.map(|row| {
        Ok(JevPrompt {
            id: row.try_get("id")?,
            questions: row.try_get("questions")?,
            first_seen: row.try_get("first_seen")?,
        })
    })
    .transpose()
}
