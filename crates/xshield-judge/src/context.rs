//! Session context: what the origin has shown one session (docs/01 section 1.2).
//!
//! Values are stored only as keyed hashes. The store lives in gateway memory;
//! a restart empties it and users re-enter through an entry.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use xshield_core::context::{IdentityRole, TraceIdentity, role_label};
use xshield_core::kind::{Rules, Shown, Used, affinity, declares, shown_as};

use crate::values::{ResponseValue, is_id_like};

/// Most values remembered per session.
pub const SEEN_MAX: usize = 5_000;
/// Most values a session may have sent that the origin had not shown it. Past
/// it the session stops learning from responses: evicting one of them would let
/// its echo be learned later.
pub const SENT_MAX: usize = SEEN_MAX;
/// Most origins of one value kept.
pub const SOURCES_MAX: usize = 6;
/// Most recent requests kept per session.
pub const RECENT_MAX: usize = 50;
/// A session with no traffic for this long is dropped.
pub const IDLE_MAX_MS: u64 = 24 * 60 * 60 * 1000;
/// Most sessions held at once.
pub const SESSIONS_MAX: usize = 20_000;
/// Values at least this long are specific enough to fast-allow when seen (the rule lives in
/// `xshield_core::kind`, where the impact preview reads it too).
pub use xshield_core::kind::LONG_VALUE_CHARS;
/// Default time a positive judgement is reused, in minutes (docs/01 section
/// 1.4 step 5). A site may change it with `advanced.allow_cache_minutes`.
pub const CACHE_MINUTES: u32 = 10;
/// [`CACHE_MINUTES`] in milliseconds.
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

/// Hex of the first 8 digest bytes: the log-safe session label (16 digits).
#[must_use]
pub fn label(digest: &Digest16) -> String {
    digest[..8].iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The number a gateway request id (`req_` and 32 hex digits) stands for;
/// 0 when the text is not one.
#[must_use]
pub fn request_number(id: &str) -> u128 {
    id.strip_prefix("req_")
        .filter(|hex| hex.len() == 32)
        .and_then(|hex| u128::from_str_radix(hex, 16).ok())
        .unwrap_or(0)
}

/// The request id a number stands for; `None` for 0, which means unknown.
#[must_use]
pub fn request_text(number: u128) -> Option<String> {
    (number != 0).then(|| format!("req_{number:032x}"))
}

/// The request whose response showed values to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source<'a> {
    /// `METHOD /path`, as the state shows it.
    pub request: &'a str,
    /// The gateway request id as a number; 0 when unknown.
    pub request_id: u128,
    /// When the response was observed, Unix milliseconds.
    pub at_ms: u64,
}

/// Where a value was seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// Field name it appeared under.
    pub field: String,
    /// The position in the response (see [`ResponseValue::at`]); empty when unknown.
    pub at: String,
    /// The request that returned it, for example `GET /api/patients`.
    pub request: String,
    /// That request's id as a number; 0 for values learned before a restart.
    pub request_id: u128,
    /// When that response was observed, Unix milliseconds; 0 when unknown.
    pub at_ms: u64,
}

/// What this session knows about one request value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    /// Up to [`SOURCES_MAX`] origins, newest last; id fields outlast others.
    pub origins: Vec<Origin>,
}

/// What an origin shows a value as, for the kind rules.
fn as_shown(origin: &Origin) -> Shown<'_> {
    Shown {
        field: &origin.field,
        request: &origin.request,
    }
}

impl Seen {
    /// Adds an origin. The same field at the same position of the same request
    /// is one origin: the first sighting is kept and a repeat changes nothing
    /// (docs/07 section 7.7.1). `(field, position, request)` decides a repeat,
    /// so the state's `seen_as` stays the same however often a list is fetched,
    /// while one field name at two positions of a response is two origins.
    fn note(&mut self, origin: Origin) {
        if self.origins.iter().any(|known| {
            known.field == origin.field && known.at == origin.at && known.request == origin.request
        }) {
            return;
        }
        if self.origins.len() >= SOURCES_MAX {
            let drop = self.eviction_index();
            self.origins.remove(drop);
        }
        self.origins.push(origin);
    }

    /// The origin that makes room when all [`SOURCES_MAX`] are kept. Small
    /// numbers repeat everywhere, so noise (a field that is not id-like, such
    /// as a stock count or an ETA) goes first, and id-like origins stay while
    /// any noise remains. Among the candidates, the oldest origin of the request
    /// that holds the most origins goes. One response that repeats an id at
    /// many positions therefore makes room from its own origins, and another
    /// response's origin goes only once no response holds more.
    fn eviction_index(&self) -> usize {
        let noise_exists = self.origins.iter().any(|origin| !is_id_like(&origin.field));
        let mut chosen: Option<(usize, usize)> = None;
        for (index, origin) in self.origins.iter().enumerate() {
            if noise_exists && is_id_like(&origin.field) {
                continue;
            }
            let held = self
                .origins
                .iter()
                .filter(|other| other.request == origin.request)
                .count();
            // Only a strictly larger share replaces the candidate, so on a tie
            // the older origin, met first, stays chosen.
            if chosen.is_none_or(|(_, best)| held > best) {
                chosen = Some((index, held));
            }
        }
        chosen.map_or(0, |(index, _)| index)
    }

    /// Whether the value is safe to fast-allow for the request that uses it.
    /// Only an id-like field shows an object reference, or a field the site
    /// declares an identifier: a value seen only under a name, a text or a note
    /// field never counts, so an echoed search query or a comment does not. A
    /// long value (at least [`LONG_VALUE_CHARS`]) then counts whatever kind of
    /// object its field names. A short value collides across unrelated objects
    /// (basket 1, product 1), so it also needs the origin to show it as the kind
    /// the request names for it (see `xshield_core::kind`).
    #[must_use]
    pub fn is_specific(&self, used: Used<'_>, rules: &Rules) -> bool {
        self.is_shown_as(used, rules, None, |_| None)
    }

    /// [`Seen::is_specific`] with the object map (the object-map design note).
    /// `request_object` is the kind the map gives the request position, and
    /// `origin_object` the kind it gives each origin's position; both are `None`
    /// where the map is silent.
    ///
    /// Where the map speaks for both sides, the two kinds decide and names do
    /// not (`doc_id` mapped to a document never counts as a doctor). Where it
    /// speaks for one side, the other side's name must name that kind. Where it
    /// is silent on both, the name rules of [`Seen::is_specific`] apply
    /// unchanged. A position the map gives a kind counts as an identifier
    /// whatever its field is called.
    #[must_use]
    pub fn is_shown_as<'a>(
        &self,
        used: Used<'_>,
        rules: &Rules,
        request_object: Option<&str>,
        origin_object: impl Fn(&Origin) -> Option<&'a str>,
    ) -> bool {
        let long = used.value.chars().count() >= LONG_VALUE_CHARS;
        self.origins.iter().any(|origin| {
            shown_as(
                used,
                as_shown(origin),
                request_object,
                origin_object(origin),
                rules,
                long,
            )
        })
    }

    /// The origins ordered for the model, most useful last: ones of the same
    /// kind of object as the request, then id fields, then the rest. The
    /// model sees only the last few, so a recent unrelated match (a stock
    /// count) must not push out the product list that really showed the id.
    #[must_use]
    pub fn ranked(&self, used: Used<'_>, rules: &Rules) -> Vec<&Origin> {
        let mut origins: Vec<&Origin> = self.origins.iter().collect();
        origins.sort_by_key(|origin| {
            let shown = as_shown(origin);
            u8::from(is_id_like(&origin.field) || declares(shown, rules))
                + 2 * u8::from(affinity(shown, used, rules))
        });
        origins
    }
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
    /// The request id as a number; 0 when unknown.
    pub request_id: u128,
    /// When the response was observed, Unix milliseconds.
    pub at_ms: u64,
}

/// An entry the session passed, and the request that passed it first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPass {
    /// The entry path.
    pub path: String,
    /// When the session first passed it, Unix milliseconds.
    pub at_ms: u64,
    /// The request that passed it; 0 when unknown.
    pub request_id: u128,
}

/// A positive judgement the cache reuses until `until_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CachedAllow {
    until_ms: u64,
    /// The request id of the Jev allow that produced it; 0 when unknown.
    source: u128,
}

/// The values a session sent, copied into a session that a response issues a
/// credential to, so that an echo in that response is not learned either.
#[derive(Debug, Clone, Default)]
pub struct SentRecord {
    overflow: bool,
    digests: HashSet<Digest16>,
}

/// Who a session is, as the origin's identity positions declared it (docs/01 section 1.2).
/// The user and the organization are keyed hashes of their ids, so the gateway never keeps an
/// id; the role is its label. A kind the session has not shown is `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionIdentity {
    user: Option<Digest16>,
    org: Option<Digest16>,
    role: Option<String>,
}

/// Domains of the identity hashes: a user id and an organization id that happen to be equal
/// are different things and hash apart.
const USER_DOMAIN: &str = "identity.user";
const ORG_DOMAIN: &str = "identity.org";

impl SessionIdentity {
    /// What one response declares: `claims` are its values at the site's identity positions,
    /// each with its kind. A kind counts only when its positions hold exactly one distinct value.
    /// A response that lists several ids declares none, because a list is not who the session is.
    #[must_use]
    pub fn declared(key: &ContextKey, claims: &[(IdentityRole, &str)]) -> Self {
        let mut users = BTreeSet::new();
        let mut orgs = BTreeSet::new();
        let mut roles = BTreeSet::new();
        for (kind, value) in claims {
            match kind {
                IdentityRole::User => {
                    users.insert(key.mac(USER_DOMAIN, value.as_bytes()));
                }
                IdentityRole::Org => {
                    orgs.insert(key.mac(ORG_DOMAIN, value.as_bytes()));
                }
                IdentityRole::Role => roles.extend(role_label(value)),
            }
        }
        Self {
            user: only(&users),
            org: only(&orgs),
            role: only(&roles),
        }
    }

    /// Takes over what `declared` says: a kind it declares replaces the session's, and a kind it
    /// does not declare is kept. An identity response is read on every call, so a switch of
    /// organization without a new login shows at once.
    pub fn update(&mut self, declared: &SessionIdentity) {
        if let Some(user) = declared.user {
            self.user = Some(user);
        }
        if let Some(org) = declared.org {
            self.org = Some(org);
        }
        if let Some(role) = &declared.role {
            self.role = Some(role.clone());
        }
    }

    /// The identity as a decision record carries it, or `None` while the session has shown none.
    #[must_use]
    pub fn tag(&self) -> Option<TraceIdentity> {
        (self.user.is_some() || self.org.is_some() || self.role.is_some()).then(|| TraceIdentity {
            user: self.user.as_ref().map(label),
            org: self.org.as_ref().map(label),
            role: self.role.clone(),
        })
    }

    /// Whether `value`, at a user-class position, is an id other than the session's own user
    /// (W6). Nothing is other while the session has shown no user, so a site without an identity
    /// position states no exposure.
    #[must_use]
    pub fn is_other_user(&self, key: &ContextKey, value: &str) -> bool {
        self.user
            .is_some_and(|user| user != key.mac(USER_DOMAIN, value.as_bytes()))
    }
}

/// The one member of a set, or `None` when the set is empty or holds several.
fn only<T: Clone + Ord>(set: &BTreeSet<T>) -> Option<T> {
    if set.len() == 1 {
        set.iter().next().cloned()
    } else {
        None
    }
}

/// Everything remembered about one session.
#[derive(Debug)]
pub struct SessionContext {
    started_ms: u64,
    last_ms: u64,
    seen: HashMap<Digest16, Seen>,
    order: VecDeque<Digest16>,
    recent: VecDeque<Recent>,
    entries: Vec<EntryPass>,
    cache: HashMap<Digest16, CachedAllow>,
    /// Values the session sent that the origin had not shown it.
    sent: HashSet<Digest16>,
    /// The session stopped learning from responses (see [`SENT_MAX`]).
    sent_overflow: bool,
    /// Who the session is, as its identity responses declared it.
    identity: SessionIdentity,
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
            sent: HashSet::new(),
            sent_overflow: false,
            identity: SessionIdentity::default(),
        }
    }

    /// Who the session is, as its identity responses declared it.
    #[must_use]
    pub fn identity(&self) -> &SessionIdentity {
        &self.identity
    }

    /// Records what a successful response declares about the session (W1). `claims` are its
    /// values at the site's identity positions. A value the session sent is not declared: an
    /// echo of what the session sent says nothing about who it is, the same rule that keeps
    /// echoes out of [`SessionContext::remember`]. Nothing is declared once the session has
    /// stopped learning from responses.
    pub fn declare_identity(&mut self, key: &ContextKey, claims: &[(IdentityRole, &str)]) {
        if self.sent_overflow {
            return;
        }
        let shown: Vec<(IdentityRole, &str)> = claims
            .iter()
            .copied()
            .filter(|(_, value)| !self.sent.contains(&key.mac("value", value.as_bytes())))
            .collect();
        self.identity
            .update(&SessionIdentity::declared(key, &shown));
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

    /// Records the values of a successful response and returns how many of
    /// them the session had not seen before. A value the session sent is not
    /// recorded: its echo shows nothing the origin showed (see
    /// [`SessionContext::note_sent`]).
    pub fn remember(
        &mut self,
        key: &ContextKey,
        source: &Source<'_>,
        values: &[ResponseValue],
    ) -> usize {
        if self.sent_overflow {
            return 0;
        }
        let mut new = 0;
        for value in values {
            let digest = key.mac("value", value.value.as_bytes());
            if self.sent.contains(&digest) {
                continue;
            }
            let origin = Origin {
                field: value.field.clone(),
                at: value.at.clone(),
                request: source.request.to_owned(),
                request_id: source.request_id,
                at_ms: source.at_ms,
            };
            if let Some(seen) = self.seen.get_mut(&digest) {
                seen.note(origin);
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
            new += 1;
        }
        new
    }

    /// Notes values this session sent in a request the origin answered. Later
    /// responses do not teach the session these values, whichever field echoes
    /// them. The record never evicts: an evicted value could be echoed back, so a
    /// session that overflows [`SENT_MAX`] stops learning from responses.
    pub fn note_sent(&mut self, digests: &[Digest16]) {
        for digest in digests {
            self.note(*digest);
        }
    }

    fn note(&mut self, digest: Digest16) {
        if self.sent_overflow || self.sent.contains(&digest) {
            return;
        }
        if self.sent.len() >= SENT_MAX {
            self.stop_learning();
            return;
        }
        self.sent.insert(digest);
    }

    /// Stops learning from responses. Used when a request's values could not all
    /// be read, so an echo of one of them cannot be told apart from what the
    /// origin shows. What was learned before stays.
    pub fn stop_learning(&mut self) {
        self.sent_overflow = true;
        self.sent.clear();
    }

    /// What the session sent, for a session that a response is about to issue a
    /// credential to.
    #[must_use]
    pub fn sent_record(&self) -> SentRecord {
        SentRecord {
            overflow: self.sent_overflow,
            digests: self.sent.clone(),
        }
    }

    /// Takes over what another session sent. A credential a response issues
    /// starts with what the request sent, so the response cannot teach it an echo.
    pub fn inherit_sent(&mut self, record: &SentRecord) {
        if record.overflow {
            self.stop_learning();
        }
        for digest in &record.digests {
            self.note(*digest);
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

    /// Notes that the session reached an entry path. Returns `true` the first
    /// time the session passes it.
    pub fn pass_entry(&mut self, path: &str, at_ms: u64, request_id: u128) -> bool {
        if self.entries.len() >= ENTRIES_MAX || self.entries.iter().any(|known| known.path == path)
        {
            return false;
        }
        self.entries.push(EntryPass {
            path: path.to_owned(),
            at_ms,
            request_id,
        });
        true
    }

    /// Entry paths reached so far, in the order first reached.
    #[must_use]
    pub fn entries_passed(&self) -> &[EntryPass] {
        &self.entries
    }

    /// The request id of the Jev allow that `cache_key` reuses, while that
    /// judgement is within its window. `Some(0)` when that request's id is
    /// unknown.
    #[must_use]
    pub fn cached_allow(&self, cache_key: &Digest16, now_ms: u64) -> Option<u128> {
        self.cache
            .get(cache_key)
            .filter(|entry| entry.until_ms > now_ms)
            .map(|entry| entry.source)
    }

    /// Remembers a positive judgement from request `source` for `ttl_ms`.
    /// Entries keep the time they were written with, so a later change of the
    /// site's cache time does not shorten or extend them.
    pub fn cache_allow(&mut self, cache_key: Digest16, now_ms: u64, ttl_ms: u64, source: u128) {
        if self.cache.len() >= CACHE_MAX {
            self.cache.retain(|_, entry| entry.until_ms > now_ms);
            if self.cache.len() >= CACHE_MAX {
                self.cache.clear();
            }
        }
        self.cache.insert(
            cache_key,
            CachedAllow {
                until_ms: now_ms + ttl_ms,
                source,
            },
        );
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

    /// What the session sent, for a session a response is about to issue a
    /// credential to. Creates nothing.
    #[must_use]
    pub fn sent_record(&self, id: &Digest16) -> SentRecord {
        self.sessions
            .get(id)
            .map_or_else(SentRecord::default, SessionContext::sent_record)
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
    /// The use of a value as the engine makes it: a path value carries the index
    /// of its segment.
    fn used<'a>(value: &'a str, path: &'a str, key: Option<&'a str>) -> Used<'a> {
        let segment = key.is_none().then(|| {
            path.split('/')
                .filter(|part| !part.is_empty())
                .position(|part| part == value)
        });
        Used {
            value,
            path,
            key,
            segment: segment.flatten(),
        }
    }

    use super::*;

    fn key() -> ContextKey {
        ContextKey::new(vec![7; 32])
    }

    fn at(request: &str) -> Source<'_> {
        Source {
            request,
            request_id: 0,
            at_ms: 0,
        }
    }

    fn response(field: &str, value: &str) -> ResponseValue {
        ResponseValue {
            at: field.to_owned(),
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
            &at("GET /api/patients"),
            &[response("id", "7"), response("age", "8")],
        );
        let seen = session.lookup(&key, "7").unwrap();
        assert_eq!(seen.origins[0].field, "id");
        assert!(seen.is_specific(used("7", "/api/patients/7", None), &Rules::default()));
        assert!(
            !session
                .lookup(&key, "8")
                .unwrap()
                .is_specific(used("8", "/api/patients/8", None), &Rules::default())
        );
        assert!(session.lookup(&key, "9").is_none());
    }

    #[test]
    fn the_field_name_decides_the_kind_and_the_best_origin_comes_last() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(
            &key,
            &at("GET /rest/products/search"),
            &[response("id", "1")],
        );
        session.remember(&key, &at("GET /api/Deliverys"), &[response("id", "1")]);
        session.remember(
            &key,
            &at("GET /api/Quantitys/"),
            &[response("quantity", "1")],
        );
        let seen = session.lookup(&key, "1").unwrap();
        assert!(seen.is_specific(
            used("1", "/rest/basket/22/checkout", Some("deliveryMethodId")),
            &Rules::default()
        ));
        assert!(!seen.is_specific(
            used("1", "/rest/basket/22/checkout", Some("couponId")),
            &Rules::default()
        ));
        assert!(seen.is_specific(
            used("1", "/api/BasketItems/", Some("ProductId")),
            &Rules::default()
        ));
        let ranked = seen.ranked(
            used("1", "/api/BasketItems/", Some("ProductId")),
            &Rules::default(),
        );
        assert_eq!(ranked.last().unwrap().request, "GET /rest/products/search");
        assert_eq!(ranked[0].field, "quantity");
    }

    #[test]
    fn a_payment_id_is_a_card_the_list_showed() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(&key, &at("GET /api/Cards"), &[response("id", "7")]);
        let seen = session.lookup(&key, "7").unwrap();
        assert!(seen.is_specific(
            used("7", "/rest/basket/22/checkout", Some("paymentId")),
            &Rules::default()
        ));
        assert!(!seen.is_specific(
            used("7", "/rest/basket/22/checkout", Some("addressId")),
            &Rules::default()
        ));
    }

    #[test]
    fn a_kind_word_inside_another_word_is_a_different_kind() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(&key, &at("GET /api/docs"), &[response("doc_id", "2")]);
        session.remember(
            &key,
            &at("GET /api/visits"),
            &[response("outpatient_id", "3"), response("clinical_id", "4")],
        );
        let document = session.lookup(&key, "2").unwrap();
        assert!(!document.is_specific(used("2", "/doctor/2", None), &Rules::default()));
        assert!(document.is_specific(used("2", "/docs/2", None), &Rules::default()));
        assert!(
            !session
                .lookup(&key, "3")
                .unwrap()
                .is_specific(used("3", "/patients/3", None), &Rules::default())
        );
        assert!(
            !session
                .lookup(&key, "4")
                .unwrap()
                .is_specific(used("4", "/clinic/4", None), &Rules::default())
        );
    }

    #[test]
    fn a_lower_case_id_compound_names_the_kind_before_its_ending() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(
            &key,
            &at("GET /api/home"),
            &[response("doctorid", "1"), response("doctorno", "5")],
        );
        let doctor = session.lookup(&key, "1").unwrap();
        assert!(doctor.is_specific(used("1", "/doctor/1", None), &Rules::default()));
        assert!(doctor.is_specific(
            used("1", "/api/doctors/1", Some("doctorId")),
            &Rules::default()
        ));
        assert!(
            session
                .lookup(&key, "5")
                .unwrap()
                .is_specific(used("5", "/api/doctors/5", None), &Rules::default())
        );
    }

    #[test]
    fn long_values_need_an_id_field_to_show_them() {
        let shown_as = |field: &str| Seen {
            origins: vec![Origin {
                field: field.into(),
                at: String::new(),
                request: "GET /x".into(),
                request_id: 0,
                at_ms: 0,
            }],
        };
        assert!(
            shown_as("patient_id").is_specific(used("P-0000042", "/x", None), &Rules::default())
        );
        assert!(!shown_as("name").is_specific(used("P-0000042", "/x", None), &Rules::default()));
        assert!(!shown_as("query").is_specific(used("P-0000042", "/x", None), &Rules::default()));
        assert!(!shown_as("name").is_specific(used("alice", "/x", None), &Rules::default()));
    }

    #[test]
    fn short_ids_only_count_for_the_same_kind_of_object() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(&key, &at("GET /api/Deliverys"), &[response("id", "1")]);
        session.remember(
            &key,
            &at("GET /rest/basket/22"),
            &[response("BasketItem.id", "9"), response("BasketId", "22")],
        );
        let delivery = session.lookup(&key, "1").unwrap();
        assert!(delivery.is_specific(used("1", "/api/Deliverys/1", None), &Rules::default()));
        assert!(!delivery.is_specific(used("1", "/rest/basket/1", None), &Rules::default()));
        session.remember(
            &key,
            &at("GET /rest/basket/22"),
            &[response("Products.id", "1")],
        );
        let both = session.lookup(&key, "1").unwrap();
        assert!(!both.is_specific(used("1", "/rest/basket/1", None), &Rules::default()));
        assert!(both.is_specific(used("1", "/api/Products/1", None), &Rules::default()));
        let item = session.lookup(&key, "9").unwrap();
        assert!(item.is_specific(used("9", "/api/BasketItems/9", None), &Rules::default()));
        assert!(session.lookup(&key, "22").unwrap().is_specific(
            used("22", "/rest/basket/22/checkout", None),
            &Rules::default()
        ));
    }

    #[test]
    fn a_path_value_takes_the_route_word_right_before_it() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(
            &key,
            &at("GET /api/doctors"),
            &[response("id", "7"), response("id", "9")],
        );
        let doctor_7 = session.lookup(&key, "7").unwrap();
        let doctor_9 = session.lookup(&key, "9").unwrap();
        let rules = Rules::default();
        let segment = |value, path, segment| Used {
            value,
            path,
            key: None,
            segment: Some(segment),
        };
        // `9` is a doctor in `/api/doctors/9`, but a file in the next path.
        assert!(doctor_9.is_specific(segment("9", "/api/doctors/9", 2), &rules));
        assert!(!doctor_9.is_specific(segment("9", "/api/doctors/7/files/9", 4), &rules));
        assert!(doctor_7.is_specific(segment("7", "/api/doctors/7/files/9", 2), &rules));
        // An id segment between a route word and the value does not hide the word.
        assert!(doctor_9.is_specific(segment("9", "/api/doctors/7/9", 3), &rules));
        // The engine decodes a segment before it is compared: `%39` is the 9 at
        // segment 4, and its route word is `files`.
        assert!(!doctor_9.is_specific(segment("9", "/api/doctors/7/files/%39", 4), &rules));
        // A value in two segments must name its kind in both of them.
        assert!(doctor_7.is_specific(segment("7", "/api/doctors/7/doctors/7", 4), &rules));
        assert!(!doctor_7.is_specific(segment("7", "/api/doctors/7/files/7", 4), &rules));
        // A segment with no route word before it takes the whole path.
        assert!(doctor_7.is_specific(segment("7", "/7/doctors", 0), &rules));
        // A named parameter still decides by its name.
        assert!(doctor_9.is_specific(used("9", "/api/files", Some("doctorId")), &rules));
    }

    #[test]
    fn a_declared_name_that_looks_like_no_id_is_an_identifier() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        session.remember(&key, &at("GET /api/home"), &[response("doc", "2")]);
        let seen = session.lookup(&key, "2").unwrap();
        let spec = xshield_core::context::SiteSpec::from_json(
            r#"{"name":"emr","hosts":["emr.test"],"origin":"http://o:1","session":{"cookie":"SID"},
               "entries":["/login"],"advanced":{"field_kinds":[{"field":"doc","kind":"doctor"}]}}"#,
        )
        .unwrap();
        let declared = Rules::of(spec.advanced());
        assert!(!is_id_like("doc"));
        assert!(!seen.is_specific(used("2", "/doctor/2", None), &Rules::default()));
        assert!(seen.is_specific(used("2", "/doctor/2", None), &declared));
    }

    #[test]
    fn origins_are_deduplicated_and_capped() {
        let key = key();
        let mut session = SessionContext::new(0);
        for index in 0..=SOURCES_MAX + 2 {
            session.remember(&key, &at(&format!("GET /r{index}")), &[response("id", "7")]);
        }
        let last = format!("GET /r{}", SOURCES_MAX + 2);
        session.remember(&key, &at(&last), &[response("id", "7")]);
        let seen = session.lookup(&key, "7").unwrap();
        assert_eq!(seen.origins.len(), SOURCES_MAX);
        assert_eq!(seen.origins.last().unwrap().request, last);
    }

    #[test]
    fn noise_origins_are_dropped_before_id_origins() {
        let key = key();
        let mut session = SessionContext::new(0);
        session.remember(&key, &at("GET /api/Products"), &[response("id", "1")]);
        for index in 0..SOURCES_MAX + 3 {
            session.remember(
                &key,
                &at(&format!("GET /s{index}")),
                &[response("quantity", "1")],
            );
        }
        let seen = session.lookup(&key, "1").unwrap();
        assert_eq!(seen.origins.len(), SOURCES_MAX);
        assert_eq!(seen.origins[0].request, "GET /api/Products");
    }

    #[test]
    fn one_response_repeating_an_id_does_not_push_out_another_responses_origin() {
        let key = key();
        let mut session = SessionContext::new(0);
        session.remember(&key, &at("GET /api/Products"), &[response("id", "1")]);
        // The same id at many positions of one response, as nested baskets
        // repeat a product id.
        let repeats: Vec<ResponseValue> = (0..SOURCES_MAX + 2)
            .map(|index| ResponseValue {
                at: format!("items[{index}].product.id"),
                field: "id".to_owned(),
                value: "1".to_owned(),
            })
            .collect();
        session.remember(&key, &at("GET /api/Baskets"), &repeats);
        let seen = session.lookup(&key, "1").unwrap();
        assert_eq!(seen.origins.len(), SOURCES_MAX);
        assert_eq!(seen.origins[0].request, "GET /api/Products");
        assert_eq!(seen.origins.last().unwrap().request, "GET /api/Baskets");
    }

    #[test]
    fn oldest_values_are_evicted_at_capacity() {
        let key = key();
        let mut session = SessionContext::new(0);
        let batch: Vec<_> = (0..SEEN_MAX + 3)
            .map(|i| response("id", &format!("v{i}")))
            .collect();
        session.remember(&key, &at("GET /x"), &batch);
        assert_eq!(session.seen_len(), SEEN_MAX);
        assert!(session.lookup(&key, "v0").is_none());
        assert!(
            session
                .lookup(&key, &format!("v{}", SEEN_MAX + 2))
                .is_some()
        );
    }

    #[test]
    fn a_repeated_field_from_one_request_keeps_its_first_origin() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        for index in 0..10u128 {
            let source = Source {
                request: "GET /api/patients",
                request_id: 100 + index,
                at_ms: 1_000 + u64::try_from(index).unwrap(),
            };
            session.remember(&key, &source, &[response("id", "7")]);
        }
        let seen = session.lookup(&key, "7").unwrap();
        assert_eq!(seen.origins.len(), 1);
        assert_eq!(
            seen.origins[0].request_id, 100,
            "the first sighting is kept"
        );
        assert_eq!(seen.origins[0].at_ms, 1_000);
        let other = Source {
            request: "GET /api/Cards",
            request_id: 200,
            at_ms: 2_000,
        };
        session.remember(&key, &other, &[response("id", "7")]);
        assert_eq!(session.lookup(&key, "7").unwrap().origins.len(), 2);
    }

    #[test]
    fn recent_requests_are_bounded_and_ordered() {
        let mut session = SessionContext::new(0);
        for index in 0..RECENT_MAX + 5 {
            session.record_request(Recent {
                request_id: 0,
                at_ms: 0,
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
            session.pass_entry(&format!("/e{}", index % (ENTRIES_MAX + 2)), 0, 0);
        }
        session.pass_entry("/e0", 0, 0);
        assert_eq!(session.entries_passed().len(), ENTRIES_MAX);
    }

    #[test]
    fn positive_judgements_expire() {
        let key = key();
        let mut session = SessionContext::new(0);
        let cache_key = key.mac("cache", b"GET /x");
        assert!(session.cached_allow(&cache_key, 0).is_none());
        session.cache_allow(cache_key, 1_000, CACHE_MS, 1);
        assert!(
            session
                .cached_allow(&cache_key, 1_000 + CACHE_MS - 1)
                .is_some()
        );
        assert!(session.cached_allow(&cache_key, 1_000 + CACHE_MS).is_none());
    }

    #[test]
    fn idle_sessions_start_over() {
        let key = key();
        let mut store = ContextStore::new();
        let id = key.mac("session", b"c");
        store
            .session(id, 0)
            .remember(&key, &at("GET /x"), &[response("id", "7")]);
        assert!(store.contains(&id, IDLE_MAX_MS));
        assert!(!store.contains(&id, IDLE_MAX_MS + 1));
        let fresh = store.session(id, IDLE_MAX_MS + 1);
        assert!(fresh.lookup(&key, "7").is_none());
        assert_eq!(fresh.age_seconds(IDLE_MAX_MS + 1), 0);
    }

    #[test]
    fn a_value_the_session_sent_is_not_learned_from_an_echo() {
        let key = key();
        let mut session = SessionContext::new(0);
        session.note_sent(&[key.mac("value", b"P-0000099")]);
        session.remember(
            &key,
            &at("GET /api/search"),
            &[
                response("patientId", "P-0000099"),
                response("patientId", "P-0000042"),
            ],
        );
        assert!(session.lookup(&key, "P-0000099").is_none());
        assert!(session.lookup(&key, "P-0000042").is_some());
    }

    #[test]
    fn a_new_credential_starts_with_what_the_request_sent() {
        let key = key();
        let mut old = SessionContext::new(0);
        old.note_sent(&[key.mac("value", b"P-0000099")]);
        let mut fresh = SessionContext::new(0);
        fresh.inherit_sent(&old.sent_record());
        fresh.remember(
            &key,
            &at("GET /api/history"),
            &[response("patientId", "P-0000099")],
        );
        assert!(fresh.lookup(&key, "P-0000099").is_none());
    }

    #[test]
    fn a_full_sent_record_stops_learning_rather_than_forgetting() {
        let key = key();
        let mut session = SessionContext::new(0);
        session.remember(&key, &at("GET /x"), &[response("id", "before")]);
        let sent: Vec<Digest16> = (0..=SENT_MAX)
            .map(|index| key.mac("value", format!("s{index}").as_bytes()))
            .collect();
        session.note_sent(&sent);
        assert_eq!(
            session.remember(&key, &at("GET /y"), &[response("id", "later")]),
            0
        );
        assert!(session.lookup(&key, "later").is_none());
        assert!(session.lookup(&key, "before").is_some());
    }

    #[test]
    fn labels_never_expose_more_than_eight_bytes() {
        assert_eq!(label(&[0xab; 16]), "abababababababab");
    }

    #[test]
    fn one_field_at_two_positions_is_two_origins_and_a_repeat_is_not_one_more() {
        let key = key();
        let mut store = ContextStore::new();
        let session = store.session(key.mac("session", b"cookie"), 0);
        let response = |position: &str| ResponseValue {
            field: "doc_id".into(),
            value: "5".into(),
            at: position.into(),
        };
        session.remember(&key, &at("GET /api/records/7"), &[response("doc_id")]);
        session.remember(
            &key,
            &at("GET /api/records/7"),
            &[response("attachments[].doc_id")],
        );
        assert_eq!(session.lookup(&key, "5").unwrap().origins.len(), 2);
        session.remember(&key, &at("GET /api/records/7"), &[response("doc_id")]);
        assert_eq!(session.lookup(&key, "5").unwrap().origins.len(), 2);
    }
}
