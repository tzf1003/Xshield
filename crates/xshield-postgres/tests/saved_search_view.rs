//! PostgreSQL wire regression for owner-scoped saved search views.

use chrono::Utc;
use serde_json::json;
use sqlx::PgPool;
use std::{env, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{SiteId, TenantId};
use xshield_postgres::{PostgresIdentityStore, SavedSearchViewCreate, SavedSearchViewWrite};

fn view_id() -> String {
    format!("view_{}", Uuid::now_v7())
}

#[tokio::test]
#[ignore = "requires XSHIELD_TEST_DATABASE_URL"]
#[allow(clippy::too_many_lines)]
async fn views_are_owner_scoped_unique_by_name_paged_and_deletable() {
    let url = env::var("XSHIELD_TEST_DATABASE_URL").expect("test database URL is required");
    let pool = PgPool::connect(&url).await.expect("test database connects");
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("database name is queryable");
    assert!(
        database.starts_with("xshield_test_"),
        "requires script-owned test database"
    );
    let store = PostgresIdentityStore::connect(&url, 3, Duration::from_secs(5))
        .await
        .expect("view store connects");
    let suffix = Uuid::now_v7().simple().to_string();
    let tenant = TenantId::parse(format!("tenant_views_{suffix}")).expect("tenant is valid");
    let site = SiteId::parse(format!("site_views_{suffix}")).expect("site is valid");
    let owner = "investigator-views";
    let other = "investigator-other-views";
    let body = json!({"schema_version": 3, "limit": 10, "sort": {"direction": "desc"}});
    let now = Utc::now();

    // Create three views for the owner; the names are unique per owner.
    let mut ids = Vec::new();
    for name in ["first", "second", "third"] {
        let id = view_id();
        let create = SavedSearchViewCreate::new(&tenant, &site, owner, &id, name, &body, now)
            .expect("view input is valid");
        assert_eq!(
            store
                .create_saved_search_view(create)
                .await
                .expect("view stores"),
            SavedSearchViewWrite::Created
        );
        ids.push(id);
    }
    ids.sort_by(|a, b| b.cmp(a));

    // The same name again is a conflict and stores nothing new.
    let duplicate = view_id();
    let create = SavedSearchViewCreate::new(&tenant, &site, owner, &duplicate, "first", &body, now)
        .expect("view input is valid");
    assert_eq!(
        store
            .create_saved_search_view(create)
            .await
            .expect("duplicate is reported"),
        SavedSearchViewWrite::NameTaken
    );

    // Another owner may reuse the same name, and sees only its own view.
    let foreign_id = view_id();
    let create =
        SavedSearchViewCreate::new(&tenant, &site, other, &foreign_id, "first", &body, now)
            .expect("view input is valid");
    assert_eq!(
        store
            .create_saved_search_view(create)
            .await
            .expect("foreign view stores"),
        SavedSearchViewWrite::Created
    );

    // Pages are descending and continue strictly below the cursor.
    let first = store
        .list_saved_search_views(&tenant, &site, owner, None, 2)
        .await
        .expect("first page reads");
    let got: Vec<&str> = first
        .items()
        .iter()
        .map(xshield_postgres::SavedSearchView::view_id)
        .collect();
    assert_eq!(got, [ids[0].as_str(), ids[1].as_str()]);
    assert_eq!(first.items()[0].request(), &body);
    let cursor = first
        .next_view_id()
        .expect("a lookahead row exists")
        .to_owned();
    let second = store
        .list_saved_search_views(&tenant, &site, owner, Some(&cursor), 2)
        .await
        .expect("second page reads");
    assert_eq!(second.items().len(), 1);
    assert_eq!(second.items()[0].view_id(), ids[2].as_str());
    assert!(second.next_view_id().is_none());

    // Another owner never sees these views.
    let others = store
        .list_saved_search_views(&tenant, &site, other, None, 10)
        .await
        .expect("other page reads");
    assert_eq!(others.items().len(), 1);
    assert_eq!(others.items()[0].view_id(), foreign_id);

    // Deleting another owner's view reports nothing deleted; the owner's delete works once.
    assert!(
        !store
            .delete_saved_search_view(&tenant, &site, owner, &foreign_id)
            .await
            .expect("cross-owner delete reads")
    );
    assert!(
        store
            .delete_saved_search_view(&tenant, &site, owner, &ids[0])
            .await
            .expect("owner delete succeeds")
    );
    assert!(
        !store
            .delete_saved_search_view(&tenant, &site, owner, &ids[0])
            .await
            .expect("repeat delete reads")
    );

    // Remove this test's rows; the database is shared by every ignored PostgreSQL test.
    sqlx::query("DELETE FROM xshield.saved_search_views WHERE tenant_id = $1")
        .bind(tenant.as_str())
        .execute(&pool)
        .await
        .expect("view cleanup succeeds");
}

#[test]
fn view_input_with_a_cursor_or_bad_shape_is_refused_before_storage() {
    let tenant = TenantId::parse("tenant_views_shape").expect("tenant is valid");
    let site = SiteId::parse("site_views_shape").expect("site is valid");
    let id = view_id();
    let now = Utc::now();
    let with_cursor = json!({"schema_version": 3, "cursor": "v1.x"});
    assert!(SavedSearchViewCreate::new(&tenant, &site, "o", &id, "n", &with_cursor, now).is_err());
    let not_object = json!(["schema_version"]);
    assert!(SavedSearchViewCreate::new(&tenant, &site, "o", &id, "n", &not_object, now).is_err());
    let oversized = json!({"schema_version": 3, "pad": "x".repeat(9000)});
    assert!(SavedSearchViewCreate::new(&tenant, &site, "o", &id, "n", &oversized, now).is_err());
    let body = json!({"schema_version": 3});
    assert!(SavedSearchViewCreate::new(&tenant, &site, "o", "view_bad", "n", &body, now).is_err());
    assert!(SavedSearchViewCreate::new(&tenant, &site, "o", &id, "bad\nname", &body, now).is_err());
    assert!(SavedSearchViewCreate::new(&tenant, &site, "o", &id, "", &body, now).is_err());
    assert!(SavedSearchViewCreate::new(&tenant, &site, "o", &id, "n", &body, now).is_ok());
}
