//! Owner-scoped saved investigation searches over HTTP:
//! `POST /control/v1/saved-views`, `GET /control/v1/saved-views[?cursor=...]` and
//! `DELETE /control/v1/saved-views/{view_id}`.
//!
//! Purpose: keep a validated search under a name so an investigator can reopen it.
//! A stored view is parameters only; reopening it runs an ordinary search, which
//! is audited on its own path.
//!
//! Invariants: tenant, site and owner come from the authenticated principal. A body
//! is accepted only if it parses as a search request for the current limits and
//! carries no cursor. Names are unique per owner. Writes pass the browser CSRF check
//! before this module runs.
//!
//! Errors: stable `CONTROL_SAVED_VIEW_*` and `CONTROL_CURSOR_*` codes. Audit: each
//! authenticated attempt appends one `console.saved_view.{create,list,delete}`
//! management event. The event carries the caller and outcome only; view identities,
//! names, search bodies and cursors stay out of the journal.

use super::{
    AccessAction, ControlPlane, CursorError, EndpointResult, api_error, component_signature,
    internal_error, lower_hex, parse_lower_hex_32, search::SearchRequest, single_header,
};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, RawQuery, State, rejection::BytesRejection, rejection::PathRejection},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;
use xshield_core::{admin::ManagementRole, constant_time};
use xshield_postgres::{SavedSearchView, SavedSearchViewCreate, SavedSearchViewWrite};

pub(super) const PATH: &str = "/control/v1/saved-views";
pub(super) const DELETE_PATH: &str = "/control/v1/saved-views/{view_id}";
/// The name and the search body are small; the cap bounds work before parsing.
pub(super) const CREATE_BODY_BYTES_MAX: usize = 9 * 1024;
const NAME_BYTES_MAX: usize = 160;
const SEARCH_BYTES_MAX: usize = 8192;
const CURSOR_PURPOSE: &[u8] = b"xshield-control-saved-view-list-v1";
const CURSOR_PARAMETER_BYTES_MAX: usize = 256;

pub(super) const LIST_ACCESS: AccessAction = AccessAction {
    event_type: "console.saved_view.list",
    method: "GET",
    path: PATH,
    role: ManagementRole::Investigator,
};
pub(super) const CREATE_ACCESS: AccessAction = AccessAction {
    event_type: "console.saved_view.create",
    method: "POST",
    path: PATH,
    role: ManagementRole::Investigator,
};
pub(super) const DELETE_ACCESS: AccessAction = AccessAction {
    event_type: "console.saved_view.delete",
    method: "DELETE",
    path: DELETE_PATH,
    role: ManagementRole::Investigator,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    schema_version: u8,
    name: String,
    search: Value,
}

#[derive(Serialize)]
struct CreateReply {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    view_id: String,
    name: String,
    created_at: String,
}

#[derive(Serialize)]
struct ListPage {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    as_of: String,
    items: Vec<Item>,
    truncated: bool,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
struct Item {
    view_id: String,
    name: String,
    search: Value,
    created_at: String,
}

#[derive(Serialize)]
struct DeleteReply {
    schema_version: u8,
    request_id: String,
    tenant_id: String,
    site_id: String,
    view_id: String,
    deleted: bool,
}

pub(super) async fn create_handler(
    State(control): State<Arc<ControlPlane>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    control
        .create_saved_view(single_header(&headers, AUTHORIZATION.as_str()), body.ok())
        .await
        .into_response()
}

pub(super) async fn list_handler(
    State(control): State<Arc<ControlPlane>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    control
        .list_saved_views(single_header(&headers, AUTHORIZATION.as_str()), raw)
        .await
        .into_response()
}

pub(super) async fn delete_handler(
    State(control): State<Arc<ControlPlane>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    control
        .delete_saved_view(
            single_header(&headers, AUTHORIZATION.as_str()),
            path.ok().map(|Path(id)| id),
        )
        .await
        .into_response()
}

/// Parses and checks a create body. The search is accepted only as a complete search
/// request with a valid plan under the current limits, and never with a cursor.
fn parse_create(bytes: &[u8], max_query_events: u16) -> Result<(String, Value), Failure> {
    if bytes.len() > CREATE_BODY_BYTES_MAX {
        return Err(Failure::Request);
    }
    let body: CreateBody = serde_json::from_slice(bytes).map_err(|_| Failure::Request)?;
    if body.schema_version != 1
        || body.name.is_empty()
        || body.name.len() > NAME_BYTES_MAX
        || body.name.chars().any(char::is_control)
    {
        return Err(Failure::Request);
    }
    let object = body.search.as_object().ok_or(Failure::Request)?;
    if object.contains_key("cursor")
        || serde_json::to_vec(&body.search).map_or(true, |text| text.len() > SEARCH_BYTES_MAX)
    {
        return Err(Failure::Request);
    }
    let request: SearchRequest =
        serde_json::from_value(body.search.clone()).map_err(|_| Failure::Request)?;
    request
        .into_plan(max_query_events)
        .map_err(|()| Failure::Request)?;
    Ok((body.name, body.search))
}

fn view_id_valid(value: &str) -> bool {
    value
        .strip_prefix("view_")
        .is_some_and(|id| Uuid::parse_str(id).is_ok_and(|id| id.get_version_num() == 7))
}

fn query(raw: Option<&str>) -> Result<Option<&str>, Failure> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let cursor = raw
        .strip_prefix("cursor=")
        .filter(|value| {
            !value.is_empty() && value.len() <= CURSOR_PARAMETER_BYTES_MAX && !value.contains('&')
        })
        .ok_or(Failure::Request)?;
    Ok(Some(cursor))
}

impl ControlPlane {
    async fn create_saved_view(
        self: Arc<Self>,
        authorization: Option<String>,
        body: Option<Bytes>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let subject = match self
            .authorize_blocking(authorization, &request_id, CREATE_ACCESS)
            .await
        {
            Ok(subject) => subject,
            Err(result) => return *result,
        };
        let parsed = body
            .as_deref()
            .ok_or(Failure::Request)
            .and_then(|bytes| parse_create(bytes, self.config.limits.max_query_events));
        let (name, search) = match parsed {
            Ok(value) => value,
            Err(failure) => {
                return self.finish_saved_view(&request_id, &subject, CREATE_ACCESS, Err(failure));
            }
        };
        let view_id = format!("view_{}", Uuid::now_v7());
        let created_at = Utc::now();
        let outcome = match self
            .create_saved_view_row(&subject, &view_id, &name, &search, created_at)
            .await
        {
            Ok(SavedSearchViewWrite::Created) => Ok(CreateReply {
                schema_version: 1,
                request_id: request_id.clone(),
                tenant_id: self.config.tenant_id.as_str().to_owned(),
                site_id: self.config.site_id.as_str().to_owned(),
                view_id,
                name,
                created_at: created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            })
            .map(|page| Outcome::Created(Json(page))),
            Ok(SavedSearchViewWrite::NameTaken) => Err(Failure::NameTaken),
            Err(failure) => Err(failure),
        };
        self.finish_saved_view_outcome(
            &request_id,
            &subject,
            CREATE_ACCESS,
            outcome,
            "CONTROL_SAVED_VIEW_CREATED",
        )
    }

    async fn list_saved_views(
        self: Arc<Self>,
        authorization: Option<String>,
        raw: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let subject = match self
            .authorize_blocking(authorization, &request_id, LIST_ACCESS)
            .await
        {
            Ok(subject) => subject,
            Err(result) => return *result,
        };
        let cursor = match query(raw.as_deref()) {
            Ok(cursor) => cursor,
            Err(failure) => {
                return self.finish_saved_view(&request_id, &subject, LIST_ACCESS, Err(failure));
            }
        };
        let before = match cursor
            .map(|c| self.decode_saved_view_cursor(&subject, c))
            .transpose()
        {
            Ok(value) => value,
            Err(error) => {
                let failure = match error {
                    CursorError::Invalid => Failure::Cursor,
                    CursorError::Unavailable => Failure::CursorUnavailable,
                };
                return self.finish_saved_view(&request_id, &subject, LIST_ACCESS, Err(failure));
            }
        };
        let outcome = self
            .saved_view_page(&request_id, &subject, before.as_deref())
            .await;
        self.finish_saved_view_outcome(
            &request_id,
            &subject,
            LIST_ACCESS,
            outcome,
            "CONTROL_SAVED_VIEWS_READ",
        )
    }

    async fn delete_saved_view(
        self: Arc<Self>,
        authorization: Option<String>,
        view_id: Option<String>,
    ) -> EndpointResult {
        let request_id = format!("req_{}", Uuid::now_v7());
        let subject = match self
            .authorize_blocking(authorization, &request_id, DELETE_ACCESS)
            .await
        {
            Ok(subject) => subject,
            Err(result) => return *result,
        };
        let Some(view_id) = view_id.filter(|id| view_id_valid(id)) else {
            return self.finish_saved_view(
                &request_id,
                &subject,
                DELETE_ACCESS,
                Err(Failure::ViewId),
            );
        };
        let outcome = match self.delete_saved_view_row(&subject, &view_id).await {
            Ok(true) => Ok(Outcome::Deleted(Json(DeleteReply {
                schema_version: 1,
                request_id: request_id.clone(),
                tenant_id: self.config.tenant_id.as_str().to_owned(),
                site_id: self.config.site_id.as_str().to_owned(),
                view_id,
                deleted: true,
            }))),
            Ok(false) => Err(Failure::NotFound),
            Err(failure) => Err(failure),
        };
        self.finish_saved_view_outcome(
            &request_id,
            &subject,
            DELETE_ACCESS,
            outcome,
            "CONTROL_SAVED_VIEW_DELETED",
        )
    }

    async fn authorize_blocking(
        self: &Arc<Self>,
        authorization: Option<String>,
        request_id: &str,
        action: AccessAction,
    ) -> Result<String, Box<EndpointResult>> {
        let control = Arc::clone(self);
        let request = request_id.to_owned();
        match tokio::task::spawn_blocking(move || {
            control.authorize(authorization.as_deref(), &request, action)
        })
        .await
        {
            Ok(Ok(subject)) => Ok(subject),
            Ok(Err(result)) => Err(result),
            Err(_) => Err(Box::new(internal_error(request_id))),
        }
    }

    async fn create_saved_view_row(
        &self,
        subject: &str,
        view_id: &str,
        name: &str,
        search: &Value,
        created_at: DateTime<Utc>,
    ) -> Result<SavedSearchViewWrite, Failure> {
        let create = SavedSearchViewCreate::new(
            &self.config.tenant_id,
            &self.config.site_id,
            subject,
            view_id,
            name,
            search,
            created_at,
        )
        .map_err(|_| Failure::Request)?;
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.catalog.create_saved_search_view(create),
        )
        .await
        .map_err(|_| Failure::Store)?
        .map_err(|_| Failure::Store)
    }

    async fn delete_saved_view_row(&self, subject: &str, view_id: &str) -> Result<bool, Failure> {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.catalog.delete_saved_search_view(
                &self.config.tenant_id,
                &self.config.site_id,
                subject,
                view_id,
            ),
        )
        .await
        .map_err(|_| Failure::Store)?
        .map_err(|_| Failure::Store)
    }

    async fn saved_view_page(
        &self,
        request_id: &str,
        subject: &str,
        before: Option<&str>,
    ) -> Result<Outcome, Failure> {
        let page = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.catalog.list_saved_search_views(
                &self.config.tenant_id,
                &self.config.site_id,
                subject,
                before,
                self.config.limits.max_query_artifacts,
            ),
        )
        .await
        .map_err(|_| Failure::Store)?
        .map_err(|_| Failure::Store)?;
        let next_cursor = page
            .next_view_id()
            .map(|id| self.encode_saved_view_cursor(subject, id))
            .transpose()
            .map_err(|()| Failure::CursorUnavailable)?;
        let millis = |value: DateTime<Utc>| value.to_rfc3339_opts(SecondsFormat::Millis, true);
        Ok(Outcome::Page(Json(ListPage {
            schema_version: 1,
            request_id: request_id.to_owned(),
            tenant_id: self.config.tenant_id.as_str().to_owned(),
            site_id: self.config.site_id.as_str().to_owned(),
            as_of: page.as_of().to_rfc3339_opts(SecondsFormat::Micros, true),
            items: page
                .items()
                .iter()
                .map(|item: &SavedSearchView| Item {
                    view_id: item.view_id().to_owned(),
                    name: item.name().to_owned(),
                    search: item.request().clone(),
                    created_at: millis(item.created_at()),
                })
                .collect(),
            truncated: next_cursor.is_some(),
            next_cursor,
        })))
    }

    fn finish_saved_view_outcome(
        &self,
        request_id: &str,
        subject: &str,
        action: AccessAction,
        outcome: Result<Outcome, Failure>,
        success_reason: &'static str,
    ) -> EndpointResult {
        match outcome {
            Ok(value) => {
                self.audit_saved_view(request_id, subject, action, "PASS", success_reason);
                match value {
                    Outcome::Created(json) => {
                        EndpointResult::Raw((StatusCode::CREATED, json).into_response())
                    }
                    Outcome::Page(json) => {
                        EndpointResult::Raw((StatusCode::OK, json).into_response())
                    }
                    Outcome::Deleted(json) => {
                        EndpointResult::Raw((StatusCode::OK, json).into_response())
                    }
                }
            }
            Err(failure) => self.finish_saved_view(request_id, subject, action, Err(failure)),
        }
    }

    fn finish_saved_view(
        &self,
        request_id: &str,
        subject: &str,
        action: AccessAction,
        result: Result<(), Failure>,
    ) -> EndpointResult {
        let failure = result.err().unwrap_or(Failure::Request);
        self.audit_saved_view(
            request_id,
            subject,
            action,
            failure.outcome(),
            failure.code(),
        );
        api_error(
            request_id,
            failure.status(),
            failure.code(),
            failure.message(),
            failure.retryable(),
            if failure.retryable() {
                "retry_later"
            } else {
                "restart_query"
            },
        )
    }

    fn audit_saved_view(
        &self,
        request_id: &str,
        subject: &str,
        action: AccessAction,
        outcome: &'static str,
        reason: &'static str,
    ) {
        // The journal keeps the caller and the outcome only; a failed journal write
        // withholds the response, as every management endpoint does.
        let _ = self.append_access_event(request_id, Some(subject), action, None, outcome, reason);
    }

    pub(super) fn encode_saved_view_cursor(&self, subject: &str, id: &str) -> Result<String, ()> {
        Ok(format!(
            "v1.{id}.{}",
            lower_hex(&self.saved_view_signature(subject, id)?)
        ))
    }

    pub(super) fn decode_saved_view_cursor(
        &self,
        subject: &str,
        cursor: &str,
    ) -> Result<String, CursorError> {
        let mut parts = cursor.split('.');
        let (Some("v1"), Some(id), Some(signature)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(CursorError::Invalid);
        };
        if parts.next().is_some() || !view_id_valid(id) {
            return Err(CursorError::Invalid);
        }
        let supplied = parse_lower_hex_32(signature).ok_or(CursorError::Invalid)?;
        let expected = self
            .saved_view_signature(subject, id)
            .map_err(|()| CursorError::Unavailable)?;
        if !constant_time::eq(&supplied, &expected) {
            return Err(CursorError::Invalid);
        }
        Ok(id.to_owned())
    }

    fn saved_view_signature(&self, subject: &str, id: &str) -> Result<[u8; 32], ()> {
        component_signature(
            &self.config.cursor_key.0,
            &[
                CURSOR_PURPOSE,
                &self.config.credential.token_digest,
                subject.as_bytes(),
                self.config.tenant_id.as_str().as_bytes(),
                self.config.site_id.as_str().as_bytes(),
                &self.config.limits.max_query_artifacts.to_be_bytes(),
                id.as_bytes(),
            ],
        )
    }
}

enum Outcome {
    Created(Json<CreateReply>),
    Page(Json<ListPage>),
    Deleted(Json<DeleteReply>),
}

#[derive(Clone, Copy)]
enum Failure {
    Request,
    ViewId,
    NameTaken,
    NotFound,
    Cursor,
    CursorUnavailable,
    Store,
}

impl Failure {
    fn status(self) -> StatusCode {
        match self {
            Self::Request | Self::ViewId | Self::Cursor => StatusCode::BAD_REQUEST,
            Self::NameTaken => StatusCode::CONFLICT,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Store | Self::CursorUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    fn outcome(self) -> &'static str {
        if self.status().is_server_error() {
            "ERROR"
        } else {
            "DENY"
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Request => "CONTROL_SAVED_VIEW_REQUEST_INVALID",
            Self::ViewId => "CONTROL_SAVED_VIEW_ID_INVALID",
            Self::NameTaken => "CONTROL_SAVED_VIEW_NAME_TAKEN",
            Self::NotFound => "CONTROL_SAVED_VIEW_NOT_FOUND",
            Self::Cursor => "CONTROL_CURSOR_INVALID",
            Self::CursorUnavailable => "CONTROL_CURSOR_UNAVAILABLE",
            Self::Store => "CONTROL_SAVED_VIEW_STORE_UNAVAILABLE",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Request => "invalid saved view request",
            Self::ViewId => "invalid saved view identifier",
            Self::NameTaken => "a saved view with this name already exists",
            Self::NotFound => "saved view not found",
            Self::Cursor => "invalid pagination cursor",
            Self::CursorUnavailable => "pagination service is temporarily unavailable",
            Self::Store => "saved view service is temporarily unavailable",
        }
    }

    fn retryable(self) -> bool {
        matches!(self, Self::Store | Self::CursorUnavailable)
    }
}
