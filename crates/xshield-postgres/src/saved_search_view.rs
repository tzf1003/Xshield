//! Owner-scoped saved investigation searches: create, keyset list and delete.
//!
//! Purpose: keep an investigator's validated search parameters under a name so
//! they can reopen the same search later. A view stores parameters only; running
//! it is an ordinary search and passes the audited search path again.
//!
//! Invariants: tenant, site and owner are bound parameters from the authenticated
//! scope. The request body is checked as an object, without a cursor and within
//! 8 KiB, both here and by the table constraints. Names are unique per owner.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::types::Json;
use xshield_core::domain::{SiteId, TenantId};

const VIEW_ID_PREFIX: &str = "view_";
const NAME_BYTES_MAX: usize = 160;
const REQUEST_BYTES_MAX: usize = 8192;

/// Validated input for one saved view.
pub struct SavedSearchViewCreate<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    owner: &'a str,
    view_id: &'a str,
    name: &'a str,
    request: &'a Value,
    created_at: DateTime<Utc>,
}

impl<'a> SavedSearchViewCreate<'a> {
    /// Checks identity, name, body and timestamp shape before any database I/O.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for a malformed view identity, owner,
    /// name, non-object or oversized body, a body carrying a cursor, or a
    /// non-finite timestamp.
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        owner: &'a str,
        view_id: &'a str,
        name: &'a str,
        request: &'a Value,
        created_at: DateTime<Utc>,
    ) -> Result<Self, StoreError> {
        if !valid_view_id(view_id)
            || owner.is_empty()
            || owner.len() > 256
            || owner.chars().any(char::is_control)
            || name.is_empty()
            || name.len() > NAME_BYTES_MAX
            || name.chars().any(char::is_control)
            || !valid_request(request)
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            owner,
            view_id,
            name,
            request,
            created_at,
        })
    }
}

fn valid_view_id(value: &str) -> bool {
    value
        .strip_prefix(VIEW_ID_PREFIX)
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok_and(|id| id.get_version_num() == 7))
}

fn valid_request(request: &Value) -> bool {
    request
        .as_object()
        .is_some_and(|object| !object.contains_key("cursor"))
        && serde_json::to_vec(request).is_ok_and(|bytes| bytes.len() <= REQUEST_BYTES_MAX)
}

/// Outcome of creating a view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SavedSearchViewWrite {
    /// The view was stored.
    Created,
    /// The owner already has a view with this name; nothing changed.
    NameTaken,
}

/// One stored view as read back for its owner.
#[derive(Clone, Debug, PartialEq)]
pub struct SavedSearchView {
    view_id: String,
    name: String,
    request: Value,
    created_at: DateTime<Utc>,
}

impl SavedSearchView {
    /// Returns the view identity.
    #[must_use]
    pub fn view_id(&self) -> &str {
        &self.view_id
    }

    /// Returns the owner-chosen name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the stored search body, without a cursor.
    #[must_use]
    pub const fn request(&self) -> &Value {
        &self.request
    }

    /// Returns the database creation time.
    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

/// One snapshot page of an owner's views, newest identity first.
pub struct SavedSearchViewPage {
    as_of: DateTime<Utc>,
    items: Vec<SavedSearchView>,
    next_view_id: Option<String>,
}

impl SavedSearchViewPage {
    /// Database observation time, present even when the page is empty.
    #[must_use]
    pub const fn as_of(&self) -> DateTime<Utc> {
        self.as_of
    }

    /// Items in strictly descending bytewise identity order.
    #[must_use]
    pub fn items(&self) -> &[SavedSearchView] {
        &self.items
    }

    /// Last emitted identity when a lookahead row exists.
    #[must_use]
    pub fn next_view_id(&self) -> Option<&str> {
        self.next_view_id.as_deref()
    }
}

impl PostgresIdentityStore {
    /// Stores one view for the owner, or reports that the name is already taken.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures other than the name conflict.
    pub async fn create_saved_search_view(
        &self,
        create: SavedSearchViewCreate<'_>,
    ) -> Result<SavedSearchViewWrite, StoreError> {
        let result = sqlx::query(
            "INSERT INTO xshield.saved_search_views (
                 tenant_id, site_id, view_id, owner_ref, name, request, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(create.tenant.as_str())
        .bind(create.site.as_str())
        .bind(create.view_id)
        .bind(create.owner)
        .bind(create.name)
        .bind(Json(create.request))
        .bind(create.created_at)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(SavedSearchViewWrite::Created),
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("23505") => {
                Ok(SavedSearchViewWrite::NameTaken)
            }
            Err(error) => Err(StoreError::from(error)),
        }
    }

    /// Lists one owner's views in one snapshot, after an optional exclusive cursor.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or a corrupt visible row,
    /// including the lookahead row used to discover another page.
    pub async fn list_saved_search_views(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        owner: &str,
        before: Option<&str>,
        limit: u16,
    ) -> Result<SavedSearchViewPage, StoreError> {
        if !(1..=128).contains(&limit) || owner.is_empty() || owner.len() > 256 {
            return Err(StoreError::InvalidCommand);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        let as_of: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let rows = sqlx::query(
            "SELECT view_id, name, request, created_at
             FROM xshield.saved_search_views
             WHERE tenant_id = $1 AND site_id = $2 AND owner_ref = $3
               AND ($4::text IS NULL OR view_id COLLATE \"C\" < $4)
             ORDER BY view_id COLLATE \"C\" DESC
             LIMIT $5",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(owner)
        .bind(before)
        .bind(i64::from(limit) + 1)
        .fetch_all(&mut *tx)
        .await?;
        tx.rollback().await?;
        decode_page(&rows, as_of, before, limit)
    }

    /// Deletes one owner's view; returns `false` when no such view exists for the owner.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures.
    pub async fn delete_saved_search_view(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        owner: &str,
        view_id: &str,
    ) -> Result<bool, StoreError> {
        if !valid_view_id(view_id) {
            return Ok(false);
        }
        let result = sqlx::query(
            "DELETE FROM xshield.saved_search_views
             WHERE tenant_id = $1 AND site_id = $2 AND owner_ref = $3 AND view_id = $4",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(owner)
        .bind(view_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}

fn decode_page(
    rows: &[sqlx::postgres::PgRow],
    as_of: DateTime<Utc>,
    before: Option<&str>,
    limit: u16,
) -> Result<SavedSearchViewPage, StoreError> {
    use sqlx::Row;
    if rows.len() > usize::from(limit) + 1 {
        return Err(StoreError::CorruptData("saved_search_view_count"));
    }
    let mut items = Vec::with_capacity(rows.len());
    let mut previous: Option<String> = before.map(str::to_owned);
    for row in rows {
        let view_id: String = row.try_get("view_id")?;
        if !valid_view_id(&view_id) {
            return Err(StoreError::CorruptData("saved_search_view_id"));
        }
        if previous
            .as_deref()
            .is_some_and(|prior| view_id.as_str() >= prior)
        {
            return Err(StoreError::CorruptData("saved_search_view_order"));
        }
        let request: Json<Value> = row.try_get("request")?;
        if !valid_request(&request.0) {
            return Err(StoreError::CorruptData("saved_search_view_request"));
        }
        previous = Some(view_id.clone());
        items.push(SavedSearchView {
            view_id,
            name: row.try_get("name")?,
            request: request.0,
            created_at: row.try_get("created_at")?,
        });
    }
    let next_view_id = if items.len() > usize::from(limit) {
        items.truncate(usize::from(limit));
        items.last().map(|item| item.view_id.clone())
    } else {
        None
    };
    Ok(SavedSearchViewPage {
        as_of,
        items,
        next_view_id,
    })
}
