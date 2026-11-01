//! Session context: what the origin has shown one session (docs/01 section 1.2).
//!
//! Values are stored only as keyed hashes. The store lives in gateway memory;
//! a restart empties it and users re-enter through an entry.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::values::{ResponseValue, is_id_like};

/// Most values remembered per session.
pub const SEEN_MAX: usize = 5_000;
/// Most origins of one value kept.
pub const SOURCES_MAX: usize = 6;
/// Most recent requests kept per session.
pub const RECENT_MAX: usize = 50;
/// A session with no traffic for this long is dropped.
pub const IDLE_MAX_MS: u64 = 24 * 60 * 60 * 1000;
/// Most sessions held at once.
pub const SESSIONS_MAX: usize = 20_000;
/// Values at least this long are specific enough to fast-allow when seen.
pub const LONG_VALUE_CHARS: usize = 8;
/// How long a positive judgement is reused (docs/01 section 1.4 step 5).
pub const CACHE_MS: u64 = 10 * 60 * 1000;
const ENTRIES_MAX: usize = 16;
const CACHE_MAX: usize = 512;

/// A keyed hash of a value or credential.
pub type Digest16 = [u8; 16];

/// Keyed hashing for values, sessions and cache keys.
#[derive(Clone)]
pub struct ContextKey(Vec<u8>);

impl ContextKey {
    /// Wraps the secret from `XSHIELD_CONTEXT_KEY_HEX`.
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self(secret)
    }

    /// HMAC-SHA256 over `domain`, a NUL, then `message`, truncated to 16 bytes.
    #[must_use]
    pub fn mac(&self, domain: &str, message: &[u8]) -> Digest16 {
        let mut tagged = Vec::with_capacity(domain.len() + 1 + message.len());
        tagged.extend_from_slice(domain.as_bytes());
        tagged.push(0);
        tagged.extend_from_slice(message);
        let full = hmac_sha256(&self.0, &tagged);
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }
}

impl std::fmt::Debug for ContextKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ContextKey(..)")
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let inner_pad: Vec<u8> = block.iter().map(|byte| byte ^ 0x36).collect();
    let outer_pad: Vec<u8> = block.iter().map(|byte| byte ^ 0x5c).collect();
    let inner = Sha256::new()
        .chain_update(&inner_pad)
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(&outer_pad)
        .chain_update(inner)
        .finalize()
        .into()
}

/// Hex of the first 4 digest bytes: the log-safe session label.
#[must_use]
pub fn label(digest: &Digest16) -> String {
    digest[..4].iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Where a value was seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// Field name it appeared under.
    pub field: String,
    /// The request that returned it, for example `GET /api/patients`.
    pub request: String,
}

/// What this session knows about one request value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// Up to [`SOURCES_MAX`] origins, newest last; id fields outlast others.
    pub origins: Vec<Origin>,
}

impl Seen {
    /// Whether the value is safe to fast-allow for a request to `path` under
    /// the field `key`: long, or seen under an id field of the same kind of
    /// object. Short values collide across unrelated objects (basket 1,
    /// product 1), so they only count when the origin field or the request
    /// that showed them names the same kind of object as the path or key.
    #[must_use]
    pub fn is_specific(&self, value: &str, path: &str, key: Option<&str>) -> bool {
        value.chars().count() >= LONG_VALUE_CHARS
            || self
                .origins
                .iter()
                .any(|origin| is_id_like(&origin.field) && affinity(origin, path, key))
    }

    /// The origins ordered for the model, most useful last: ones of the same
    /// kind of object as the request, then id fields, then the rest. The
    /// model sees only the last few, so a recent unrelated match (a stock
    /// count) must not push out the product list that really showed the id.
    #[must_use]
    pub fn ranked(&self, path: &str, key: Option<&str>) -> Vec<&Origin> {
        let mut origins: Vec<&Origin> = self.origins.iter().collect();
        origins.sort_by_key(|origin| {
            u8::from(is_id_like(&origin.field)) + 2 * u8::from(affinity(origin, path, key))
        });
        origins
    }
}

fn affinity(origin: &Origin, path: &str, key: Option<&str>) -> bool {
    // A field name says what kind of object the value selects; only without
    // one (a path segment, a bare `id` field) does the path decide.
    let by_key = key.map(kind_words).unwrap_or_default();
    let wanted = if by_key.is_empty() {
        kind_words(path)
    } else {
        by_key
    };
    // The field's own name says what it identifies (`ProductId` is a
    // product, whatever object carried it); a bare `id` takes the kind of its
    // parent (`Products.id`), and a bare top-level `id` the kind of the
    // request that returned it.
    let (parent, last) = origin.field.rsplit_once('.').unwrap_or(("", &origin.field));
    let mut shown = kind_words(last);
    if shown.is_empty() {
        shown = kind_words(parent);
    }
    if shown.is_empty() {
        shown = kind_words(origin.request.split_once(' ').map_or("", |(_, path)| path));
    }
    wanted
        .iter()
        .any(|word| shown.iter().any(|other| related(word, other)))
}

const GENERIC_WORDS: [&str; 8] = ["api", "rest", "v1", "v2", "v3", "data", "value", "id"];

/// Lower-cased words of a path or field name, camel case split, plural
/// endings and generic route prefixes removed: `/api/Addresss/7` gives
/// `address`, `ProductId` gives `product`.
fn kind_words(text: &str) -> Vec<String> {
    let mut spaced = String::with_capacity(text.len() + 8);
    let mut previous_lower = false;
    for c in text.chars() {
        if c.is_ascii_uppercase() && previous_lower {
            spaced.push(' ');
        }
        previous_lower = c.is_ascii_lowercase();
        spaced.push(c);
    }
    spaced
        .split(|c: char| !c.is_ascii_alphabetic())
        .map(|word| word.to_ascii_lowercase().trim_end_matches('s').to_owned())
        .filter(|word| word.len() >= 3 && !GENERIC_WORDS.contains(&word.as_str()))
        .collect()
}

/// Words for one kind of object that differ between a field and the endpoint
/// that lists it (`paymentId` selects a card of `/api/Cards`).
const SYNONYMS: [(&str, &str); 1] = [("payment", "card")];

fn related(left: &str, right: &str) -> bool {
    left.contains(right)
        || right.contains(left)
        || SYNONYMS.iter().any(|(first, second)| {
            (left.contains(first) && right.contains(second))
                || (left.contains(second) && right.contains(first))
        })
}

/// One remembered request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recent {
    /// HTTP method.
    pub method: String,
    /// Path without query.
    pub path: String,
    /// Origin status.
    pub status: u16,
}

/// Everything remembered about one session.
#[derive(Debug)]
pub struct SessionContext {
    started_ms: u64,
    last_ms: u64,
    seen: HashMap<Digest16, Seen>,
    order: VecDeque<Digest16>,
    recent: VecDeque<Recent>,
    entries: Vec<String>,
    cache: HashMap<Digest16, u64>,
}

impl SessionContext {
    fn new(now_ms: u64) -> Self {
        Self {
            started_ms: now_ms,
            last_ms: now_ms,
            seen: HashMap::new(),
            order: VecDeque::new(),
            recent: VecDeque::new(),
            entries: Vec::new(),
            cache: HashMap::new(),
        }
    }

    /// Seconds since the session was first seen.
    #[must_use]
    pub fn age_seconds(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.started_ms) / 1000
    }

    /// What is known about `value`, if anything.
    #[must_use]
    pub fn lookup(&self, key: &ContextKey, value: &str) -> Option<&Seen> {
        self.seen.get(&key.mac("value", value.as_bytes()))
    }

    /// Records the values of a successful response to `request`.
    pub fn remember(&mut self, key: &ContextKey, request: &str, values: &[ResponseValue]) {
        for value in values {
            let digest = key.mac("value", value.value.as_bytes());
            let origin = Origin {
                field: value.field.clone(),
                request: request.to_owned(),
            };
            if let Some(seen) = self.seen.get_mut(&digest) {
                if !seen.origins.contains(&origin) {
                    if seen.origins.len() == SOURCES_MAX {
                        // Small numbers repeat everywhere; keep the id-field
                        // origins that really identify an object and drop
                        // the noise (a stock count, an ETA) first.
                        let drop = seen
                            .origins
                            .iter()
                            .position(|o| !is_id_like(&o.field))
                            .unwrap_or(0);
                        seen.origins.remove(drop);
                    }
                    seen.origins.push(origin);
                }
                continue;
            }
            if self.order.len() >= SEEN_MAX
                && let Some(oldest) = self.order.pop_front()
            {
                self.seen.remove(&oldest);
            }
            self.seen.insert(
                digest,
                Seen {
                    origins: vec![origin],
                },
            );
            self.order.push_back(digest);
        }
    }

    /// Appends one request to the recent list.
    pub fn record_request(&mut self, recent: Recent) {
        if self.recent.len() == RECENT_MAX {
            self.recent.pop_front();
        }
        self.recent.push_back(recent);
    }

    /// The last `limit` requests, oldest first.
    #[must_use]
    pub fn recent(&self, limit: usize) -> Vec<&Recent> {
        let skip = self.recent.len().saturating_sub(limit);
        self.recent.iter().skip(skip).collect()
    }

    /// Notes that the session reached an entry path.
    pub fn pass_entry(&mut self, path: &str) {
        if self.entries.len() < ENTRIES_MAX && !self.entries.iter().any(|known| known == path) {
            self.entries.push(path.to_owned());
        }
    }

    /// Entry paths reached so far.
    #[must_use]
    pub fn entries_passed(&self) -> &[String] {
        &self.entries
    }

    /// Whether `cache_key` was judged safe within [`CACHE_MS`].
    #[must_use]
    pub fn cached_allow(&self, cache_key: &Digest16, now_ms: u64) -> bool {
        self.cache
            .get(cache_key)
            .is_some_and(|until| *until > now_ms)
    }

    /// Remembers a positive judgement.
    pub fn cache_allow(&mut self, cache_key: Digest16, now_ms: u64) {
        if self.cache.len() >= CACHE_MAX {
            self.cache.retain(|_, until| *until > now_ms);
            if self.cache.len() >= CACHE_MAX {
                self.cache.clear();
            }
        }
        self.cache.insert(cache_key, now_ms + CACHE_MS);
    }

    /// Number of remembered values.
    #[must_use]
    pub fn seen_len(&self) -> usize {
        self.seen.len()
    }
}

/// All sessions of one gateway process.
#[derive(Debug, Default)]
pub struct ContextStore {
    sessions: HashMap<Digest16, SessionContext>,
}

impl ContextStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The session for `id`, created when absent. Expired sessions are
    /// replaced by fresh ones; at capacity the least recently active goes.
    pub fn session(&mut self, id: Digest16, now_ms: u64) -> &mut SessionContext {
        if self
            .sessions
            .get(&id)
            .is_some_and(|session| now_ms.saturating_sub(session.last_ms) > IDLE_MAX_MS)
        {
            self.sessions.remove(&id);
        }
        if !self.sessions.contains_key(&id) && self.sessions.len() >= SESSIONS_MAX {
            self.sessions
                .retain(|_, session| now_ms.saturating_sub(session.last_ms) <= IDLE_MAX_MS);
            if self.sessions.len() >= SESSIONS_MAX
                && let Some(oldest) = self
                    .sessions
                    .iter()
                    .min_by_key(|(_, s)| s.last_ms)
                    .map(|(k, _)| *k)
            {
                self.sessions.remove(&oldest);
            }
        }
        let session = self
            .sessions
            .entry(id)
            .or_insert_with(|| SessionContext::new(now_ms));
        session.last_ms = now_ms;
        session
    }

    /// Whether a live session exists for `id`.
    #[must_use]
    pub fn contains(&self, id: &Digest16, now_ms: u64) -> bool {
        self.sessions
            .get(id)
            .is_some_and(|session| now_ms.saturating_sub(session.last_ms) <= IDLE_MAX_MS)
    }

    /// Number of sessions held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether no session is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ContextKey {
        ContextKey::new(vec![7; 32])
    }

    fn response(field: &str, value: &str) -> ResponseValue {
        ResponseValue {
            field: field.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex = mac.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        });
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn mac_separates_domains_and_keys() {
        let a = key();
        assert_ne!(a.mac("value", b"x"), a.mac("session", b"x"));
        assert_ne!(
            a.mac("value", b"x"),
            ContextKey::new(vec![8; 32]).mac("value", b"x")
        );
        assert_eq!(a.mac("value", b"x"), a.mac("value", b"x"));
    }

    #[test]
    fn remembered_values_are_found_with_origins() {
        let key = key();
        let mut store = ContextStore::new();
        let id = key.mac("session", b"cookie");
        let session = store.session(id, 0);
        session.remember(
            &key,
            "GET /api/patients",
            &[response("id", "7"), response("age", "8")],
        );
        let seen = session.lookup(&key, "7").unwrap();
        assert_eq!(seen.origins[0].field, "id");
        assert!(seen.is_specific("7", "/api/patients/7", None));
        assert!(
            !session
                .lookup(&key, "8")
                .unwrap()
                .is_specific("8", "/api/patients/8", None)
        );
        assert!(session.lookup(&key, "9").is_none());
    }

    #[test]
    fn the_field_name_decides_the_kind_and_the_best_origin_comes_last() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(&key, "GET /rest/products/search", &[response("id", "1")]);
        session.remember(&key, "GET /api/Deliverys", &[response("id", "1")]);
        session.remember(&key, "GET /api/Quantitys/", &[response("quantity", "1")]);
        let seen = session.lookup(&key, "1").unwrap();
        assert!(seen.is_specific("1", "/rest/basket/22/checkout", Some("deliveryMethodId")));
        assert!(!seen.is_specific("1", "/rest/basket/22/checkout", Some("couponId")));
        assert!(seen.is_specific("1", "/api/BasketItems/", Some("ProductId")));
        let ranked = seen.ranked("/api/BasketItems/", Some("ProductId"));
        assert_eq!(ranked.last().unwrap().request, "GET /rest/products/search");
        assert_eq!(ranked[0].field, "quantity");
    }

    #[test]
    fn a_payment_id_is_a_card_the_list_showed() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(&key, "GET /api/Cards", &[response("id", "7")]);
        let seen = session.lookup(&key, "7").unwrap();
        assert!(seen.is_specific("7", "/rest/basket/22/checkout", Some("paymentId")));
        assert!(!seen.is_specific("7", "/rest/basket/22/checkout", Some("addressId")));
    }

    #[test]
    fn long_values_are_specific_whatever_their_field() {
        let seen = Seen {
            origins: vec![Origin {
                field: "name".into(),
                request: "GET /x".into(),
            }],
        };
        assert!(seen.is_specific("P-0000042", "/x", None));
        assert!(!seen.is_specific("alice", "/x", None));
    }

    #[test]
    fn short_ids_only_count_for_the_same_kind_of_object() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(&key, "GET /api/Deliverys", &[response("id", "1")]);
        session.remember(
            &key,
            "GET /rest/basket/22",
            &[response("BasketItem.id", "9"), response("BasketId", "22")],
        );
        let delivery = session.lookup(&key, "1").unwrap();
        assert!(delivery.is_specific("1", "/api/Deliverys/1", None));
        assert!(!delivery.is_specific("1", "/rest/basket/1", None));
        session.remember(&key, "GET /rest/basket/22", &[response("Products.id", "1")]);
        let both = session.lookup(&key, "1").unwrap();
        assert!(!both.is_specific("1", "/rest/basket/1", None));
        assert!(both.is_specific("1", "/api/Products/1", None));
        let item = session.lookup(&key, "9").unwrap();
        assert!(item.is_specific("9", "/api/BasketItems/9", None));
        assert!(session.lookup(&key, "22").unwrap().is_specific(
            "22",
            "/rest/basket/22/checkout",
            None
        ));
    }

    #[test]
    fn origins_are_deduplicated_and_capped() {
        let key = key();
        let mut session = SessionContext::new(0);
        for index in 0..=SOURCES_MAX + 2 {
            session.remember(&key, &format!("GET /r{index}"), &[response("id", "7")]);
        }
        let last = format!("GET /r{}", SOURCES_MAX + 2);
        session.remember(&key, &last, &[response("id", "7")]);
        let seen = session.lookup(&key, "7").unwrap();
        assert_eq!(seen.origins.len(), SOURCES_MAX);
        assert_eq!(seen.origins.last().unwrap().request, last);
    }

    #[test]
    fn noise_origins_are_dropped_before_id_origins() {
        let key = key();
        let mut session = SessionContext::new(0);
        session.remember(&key, "GET /api/Products", &[response("id", "1")]);
        for index in 0..SOURCES_MAX + 3 {
            session.remember(
                &key,
                &format!("GET /s{index}"),
                &[response("quantity", "1")],
            );
        }
        let seen = session.lookup(&key, "1").unwrap();
        assert_eq!(seen.origins.len(), SOURCES_MAX);
        assert_eq!(seen.origins[0].request, "GET /api/Products");
    }

    #[test]
    fn oldest_values_are_evicted_at_capacity() {
        let key = key();
        let mut session = SessionContext::new(0);
        let batch: Vec<_> = (0..SEEN_MAX + 3)
            .map(|i| response("id", &format!("v{i}")))
            .collect();
        session.remember(&key, "GET /x", &batch);
        assert_eq!(session.seen_len(), SEEN_MAX);
        assert!(session.lookup(&key, "v0").is_none());
        assert!(
            session
                .lookup(&key, &format!("v{}", SEEN_MAX + 2))
                .is_some()
        );
    }

    #[test]
    fn recent_requests_are_bounded_and_ordered() {
        let mut session = SessionContext::new(0);
        for index in 0..RECENT_MAX + 5 {
            session.record_request(Recent {
                method: "GET".into(),
                path: format!("/{index}"),
                status: 200,
            });
        }
        let last = session.recent(3);
        assert_eq!(last.len(), 3);
        assert_eq!(last[2].path, format!("/{}", RECENT_MAX + 4));
        assert_eq!(session.recent(1000).len(), RECENT_MAX);
    }

    #[test]
    fn entries_are_deduplicated_and_capped() {
        let mut session = SessionContext::new(0);
        for index in 0..ENTRIES_MAX + 4 {
            session.pass_entry(&format!("/e{}", index % (ENTRIES_MAX + 2)));
        }
        session.pass_entry("/e0");
        assert_eq!(session.entries_passed().len(), ENTRIES_MAX);
    }

    #[test]
    fn positive_judgements_expire() {
        let key = key();
        let mut session = SessionContext::new(0);
        let cache_key = key.mac("cache", b"GET /x");
        assert!(!session.cached_allow(&cache_key, 0));
        session.cache_allow(cache_key, 1_000);
        assert!(session.cached_allow(&cache_key, 1_000 + CACHE_MS - 1));
        assert!(!session.cached_allow(&cache_key, 1_000 + CACHE_MS));
    }

    #[test]
    fn idle_sessions_start_over() {
        let key = key();
        let mut store = ContextStore::new();
        let id = key.mac("session", b"c");
        store
            .session(id, 0)
            .remember(&key, "GET /x", &[response("id", "7")]);
        assert!(store.contains(&id, IDLE_MAX_MS));
        assert!(!store.contains(&id, IDLE_MAX_MS + 1));
        let fresh = store.session(id, IDLE_MAX_MS + 1);
        assert!(fresh.lookup(&key, "7").is_none());
        assert_eq!(fresh.age_seconds(IDLE_MAX_MS + 1), 0);
    }

    #[test]
    fn labels_never_expose_more_than_four_bytes() {
        assert_eq!(label(&[0xab; 16]), "abababab");
    }
}
