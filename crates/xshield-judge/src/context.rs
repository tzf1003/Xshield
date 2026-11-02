//! Session context: what the origin has shown one session (docs/01 section 1.2).
//!
//! Values are stored only as keyed hashes. The store lives in gateway memory;
//! a restart empties it and users re-enter through an entry.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::values::{ResponseValue, is_id_like, percent_decode};

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
/// Values at least this long are specific enough to fast-allow when seen.
pub const LONG_VALUE_CHARS: usize = 8;
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

impl Seen {
    /// Adds an origin. The same field from the same request is one origin: the
    /// first sighting is kept and a repeat changes nothing (docs/07 section
    /// 7.7.1). Only `(field, request)` decides a repeat, so the state's
    /// `seen_as` stays the same however often a list is fetched.
    fn note(&mut self, origin: Origin) {
        if self
            .origins
            .iter()
            .any(|known| known.field == origin.field && known.request == origin.request)
        {
            return;
        }
        if self.origins.len() == SOURCES_MAX {
            // Small numbers repeat everywhere; keep the id-field origins that
            // really identify an object and drop the noise (a stock count, an
            // ETA) first.
            let drop = self
                .origins
                .iter()
                .position(|o| !is_id_like(&o.field))
                .unwrap_or(0);
            self.origins.remove(drop);
        }
        self.origins.push(origin);
    }

    /// Whether the value is safe to fast-allow for a request to `path` under
    /// the field `key`. Only an id-like field shows an object reference: a value
    /// seen only under a name, a text or a note field never counts, so an echoed
    /// search query or a comment does not. A long value (at least
    /// [`LONG_VALUE_CHARS`]) then counts whatever kind of object its field
    /// names. A short value collides across unrelated objects (basket 1,
    /// product 1), so it also needs the origin field or the request that showed
    /// it to name the same kind of object as the path or key. `synonyms` are the
    /// site's extra pairs (see [`site_synonym`]).
    #[must_use]
    pub fn is_specific(
        &self,
        value: &str,
        path: &str,
        key: Option<&str>,
        synonyms: &[(String, String)],
    ) -> bool {
        let long = value.chars().count() >= LONG_VALUE_CHARS;
        self.origins.iter().any(|origin| {
            is_id_like(&origin.field) && (long || affinity(origin, value, path, key, synonyms))
        })
    }

    /// The origins ordered for the model, most useful last: ones of the same
    /// kind of object as the request, then id fields, then the rest. The
    /// model sees only the last few, so a recent unrelated match (a stock
    /// count) must not push out the product list that really showed the id.
    #[must_use]
    pub fn ranked(
        &self,
        value: &str,
        path: &str,
        key: Option<&str>,
        synonyms: &[(String, String)],
    ) -> Vec<&Origin> {
        let mut origins: Vec<&Origin> = self.origins.iter().collect();
        origins.sort_by_key(|origin| {
            u8::from(is_id_like(&origin.field))
                + 2 * u8::from(affinity(origin, value, path, key, synonyms))
        });
        origins
    }
}

/// A site's synonym pair as the context compares it: the same reduction
/// `kind_words` applies to field and path names (lower case, trailing `s`
/// removed), so `address` matches the `addre` that `/api/Addresss` yields.
/// A pair with a word shorter than three letters after that is dropped: an
/// empty word would match every field.
#[must_use]
pub fn site_synonym(first: &str, second: &str) -> Option<(String, String)> {
    let first = first.to_ascii_lowercase();
    let second = second.to_ascii_lowercase();
    let (first, second) = (first.trim_end_matches('s'), second.trim_end_matches('s'));
    (first.len() >= 3 && second.len() >= 3).then(|| (first.to_owned(), second.to_owned()))
}

/// Whether the origin shows the value as the kind of object every use of it in
/// the request names (see [`wanted_kinds`]).
fn affinity(
    origin: &Origin,
    value: &str,
    path: &str,
    key: Option<&str>,
    synonyms: &[(String, String)],
) -> bool {
    let shown = shown_kinds(origin);
    let wanted = wanted_kinds(value, path, key);
    !wanted.is_empty()
        && wanted.iter().all(|words| {
            words
                .iter()
                .any(|word| shown.iter().any(|other| related(word, other, synonyms)))
        })
}

/// The kinds an origin shows a value as. The field's own name says what it
/// identifies (`ProductId` is a product, whatever object carried it); a bare
/// `id` takes the kind of its parent (`Products.id`), and a bare top-level `id`
/// the kind of the request that returned it.
fn shown_kinds(origin: &Origin) -> Vec<String> {
    let (parent, last) = origin.field.rsplit_once('.').unwrap_or(("", &origin.field));
    let mut shown = kind_words(last);
    if shown.is_empty() {
        shown = kind_words(parent);
    }
    if shown.is_empty() {
        shown = kind_words(origin.request.split_once(' ').map_or("", |(_, path)| path));
    }
    shown
}

/// The kinds each use of the value in the request names, one list per use.
///
/// A query, form or body value takes the kind its key names, or the whole
/// path's kinds when the key names none (a bare `id`). A path segment has no
/// key: it takes the route word nearest before it, so in
/// `/api/doctors/7/files/9` the 9 is a file whatever else the path names, and
/// only a segment with no route word before it takes the whole path. A value
/// that occurs in several segments names its kind in each of them. Segments
/// are compared decoded, as the values were extracted.
fn wanted_kinds(value: &str, path: &str, key: Option<&str>) -> Vec<Vec<String>> {
    let by_key = key.map(kind_words).unwrap_or_default();
    if !by_key.is_empty() {
        return vec![by_key];
    }
    let whole = kind_words(path);
    if key.is_some() {
        return vec![whole];
    }
    let segments: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let uses: Vec<Vec<String>> = segments
        .iter()
        .enumerate()
        .filter(|&(_, segment)| percent_decode(segment, false) == value)
        .map(|(index, _)| {
            segments[..index]
                .iter()
                .rev()
                .map(|segment| kind_words(segment))
                .find(|words| !words.is_empty())
                .unwrap_or_else(|| whole.clone())
        })
        .collect();
    if uses.is_empty() { vec![whole] } else { uses }
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

/// Identifier endings a compound word may carry (`doctorid`, `patientno`).
/// Longer endings come first so that `uuid` is not read as `id`.
const ID_SUFFIXES: [&str; 6] = ["uuid", "code", "num", "ref", "id", "no"];

/// The kind a word names: a compound with an identifier ending loses the ending
/// (`doctorid` names a doctor); any other word is its own kind. Containment does
/// not make two words one kind: `doc` is part of `doctor`, and `outpatient` of
/// `patient`, so a document id must not unlock a doctor path.
fn kind_of(word: &str) -> &str {
    ID_SUFFIXES
        .into_iter()
        .find_map(|suffix| word.strip_suffix(suffix))
        .filter(|rest| rest.len() >= 3)
        .unwrap_or(word)
}

fn same_kind(left: &str, right: &str) -> bool {
    kind_of(left) == kind_of(right)
}

/// Whether two words name the same kind of object, or are a built-in or site
/// synonym pair.
fn related(left: &str, right: &str, synonyms: &[(String, String)]) -> bool {
    let pairs = SYNONYMS
        .iter()
        .map(|(first, second)| (*first, *second))
        .chain(
            synonyms
                .iter()
                .map(|(first, second)| (first.as_str(), second.as_str())),
        );
    same_kind(left, right)
        || pairs.into_iter().any(|(first, second)| {
            (same_kind(left, first) && same_kind(right, second))
                || (same_kind(left, second) && same_kind(right, first))
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
        assert!(seen.is_specific("7", "/api/patients/7", None, &[]));
        assert!(
            !session
                .lookup(&key, "8")
                .unwrap()
                .is_specific("8", "/api/patients/8", None, &[])
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
            "1",
            "/rest/basket/22/checkout",
            Some("deliveryMethodId"),
            &[]
        ));
        assert!(!seen.is_specific("1", "/rest/basket/22/checkout", Some("couponId"), &[]));
        assert!(seen.is_specific("1", "/api/BasketItems/", Some("ProductId"), &[]));
        let ranked = seen.ranked("1", "/api/BasketItems/", Some("ProductId"), &[]);
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
        assert!(seen.is_specific("7", "/rest/basket/22/checkout", Some("paymentId"), &[]));
        assert!(!seen.is_specific("7", "/rest/basket/22/checkout", Some("addressId"), &[]));
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
        assert!(!document.is_specific("2", "/doctor/2", None, &[]));
        assert!(document.is_specific("2", "/docs/2", None, &[]));
        assert!(
            !session
                .lookup(&key, "3")
                .unwrap()
                .is_specific("3", "/patients/3", None, &[])
        );
        assert!(
            !session
                .lookup(&key, "4")
                .unwrap()
                .is_specific("4", "/clinic/4", None, &[])
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
        assert!(doctor.is_specific("1", "/doctor/1", None, &[]));
        assert!(doctor.is_specific("1", "/api/doctors/1", Some("doctorId"), &[]));
        assert!(
            session
                .lookup(&key, "5")
                .unwrap()
                .is_specific("5", "/api/doctors/5", None, &[])
        );
    }

    #[test]
    fn long_values_need_an_id_field_to_show_them() {
        let shown_as = |field: &str| Seen {
            origins: vec![Origin {
                field: field.into(),
                request: "GET /x".into(),
                request_id: 0,
                at_ms: 0,
            }],
        };
        assert!(shown_as("patient_id").is_specific("P-0000042", "/x", None, &[]));
        assert!(!shown_as("name").is_specific("P-0000042", "/x", None, &[]));
        assert!(!shown_as("query").is_specific("P-0000042", "/x", None, &[]));
        assert!(!shown_as("name").is_specific("alice", "/x", None, &[]));
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
        assert!(delivery.is_specific("1", "/api/Deliverys/1", None, &[]));
        assert!(!delivery.is_specific("1", "/rest/basket/1", None, &[]));
        session.remember(
            &key,
            &at("GET /rest/basket/22"),
            &[response("Products.id", "1")],
        );
        let both = session.lookup(&key, "1").unwrap();
        assert!(!both.is_specific("1", "/rest/basket/1", None, &[]));
        assert!(both.is_specific("1", "/api/Products/1", None, &[]));
        let item = session.lookup(&key, "9").unwrap();
        assert!(item.is_specific("9", "/api/BasketItems/9", None, &[]));
        assert!(session.lookup(&key, "22").unwrap().is_specific(
            "22",
            "/rest/basket/22/checkout",
            None,
            &[]
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
        // `9` is a doctor in `/api/doctors/9`, but a file in the next path.
        assert!(doctor_9.is_specific("9", "/api/doctors/9", None, &[]));
        assert!(!doctor_9.is_specific("9", "/api/doctors/7/files/9", None, &[]));
        assert!(doctor_7.is_specific("7", "/api/doctors/7/files/9", None, &[]));
        // An id segment between a route word and the value does not hide the word.
        assert!(doctor_9.is_specific("9", "/api/doctors/7/9", None, &[]));
        // The same segment, percent-encoded, is the same value.
        assert!(!doctor_9.is_specific("9", "/api/doctors/7/files/%39", None, &[]));
        // A value in two segments must name its kind in both of them.
        assert!(!doctor_7.is_specific("7", "/api/doctors/7/files/7", None, &[]));
        assert!(doctor_7.is_specific("7", "/api/doctors/7/doctors/7", None, &[]));
        // A segment with no route word before it takes the whole path.
        assert!(doctor_7.is_specific("7", "/7/doctors", None, &[]));
        // A named parameter still decides by its name.
        assert!(doctor_9.is_specific("9", "/api/files", Some("doctorId"), &[]));
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
}
