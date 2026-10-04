//! Process-local per-source request metering for protected sites.
//!
//! The table is bounded and never refuses a source because it is full: a new
//! source evicts the least recently referenced one (CLOCK second chance, so an
//! insertion is amortized O(1) and walks no table). It is split into shards so
//! one hot site does not serialize every request behind a single lock, and keys
//! are keyed 64-bit hashes so the hot path allocates nothing.
//!
//! Eviction trades memory for precision: a source whose bucket was evicted
//! starts again with a full burst. That is deliberate, since the alternative
//! (denying new sources while the table is full) lets an attacker with many
//! source addresses lock out every legitimate newcomer, and an evicted bucket
//! can only belong to a source that had been quiet longer than the others.

use std::{
    collections::HashMap,
    hash::BuildHasher,
    net::{IpAddr, Ipv6Addr},
    sync::Mutex,
    time::Instant,
};

const SHARDS: usize = 16;
const DEFAULT_SLOTS_PER_SHARD: usize = 4_096;

struct Slot {
    key: u64,
    tokens: f64,
    updated: Instant,
    /// CLOCK reference bit: set on every use, cleared as the hand passes.
    referenced: bool,
}

#[derive(Default)]
struct Shard {
    slots: Vec<Slot>,
    index: HashMap<u64, usize>,
    hand: usize,
}

impl Shard {
    /// Returns the slot for `key`, evicting a cold entry when the shard is full.
    /// A freshly created slot holds a full `burst`.
    fn slot(&mut self, key: u64, capacity: usize, burst: f64, now: Instant) -> &mut Slot {
        if let Some(&position) = self.index.get(&key) {
            let slot = &mut self.slots[position];
            slot.referenced = true;
            return slot;
        }
        let fresh = Slot {
            key,
            tokens: burst,
            updated: now,
            referenced: true,
        };
        let position = if self.slots.len() < capacity {
            self.slots.push(fresh);
            self.slots.len() - 1
        } else {
            // Second chance: clear reference bits until an unreferenced victim
            // appears. Every clear was paid for by an earlier reference, so the
            // sweep is amortized O(1); one pass always finds a victim.
            loop {
                let candidate = self.hand;
                self.hand = (self.hand + 1) % self.slots.len();
                if self.slots[candidate].referenced {
                    self.slots[candidate].referenced = false;
                } else {
                    self.index.remove(&self.slots[candidate].key);
                    self.slots[candidate] = fresh;
                    break candidate;
                }
            }
        };
        self.index.insert(key, position);
        &mut self.slots[position]
    }
}

pub(crate) struct SiteRateLimiter {
    // ponytail: process-local source buckets; use a shared limiter when edge replicas need one quota.
    shards: Vec<Mutex<Shard>>,
    slots_per_shard: usize,
    hasher: std::collections::hash_map::RandomState,
}

/// IPv6 sources are metered per /64: one subscriber owns the whole prefix, so
/// per-address buckets would let a single host mint unlimited fresh buckets.
fn meter_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

impl SiteRateLimiter {
    pub(crate) fn new() -> Self {
        Self::with_capacity(SHARDS, DEFAULT_SLOTS_PER_SHARD)
    }

    /// A limiter with `shards` locks of `slots_per_shard` buckets each.
    pub(crate) fn with_capacity(shards: usize, slots_per_shard: usize) -> Self {
        let shards = shards.max(1);
        Self {
            shards: (0..shards).map(|_| Mutex::new(Shard::default())).collect(),
            slots_per_shard: slots_per_shard.max(1),
            hasher: std::collections::hash_map::RandomState::new(),
        }
    }

    /// Takes one token for `(site, source)`; `false` when the source is over its
    /// budget or cannot be identified. A source never loses admission because
    /// other sources fill the table.
    pub(crate) fn allow(
        &self,
        site_id: &str,
        source: Option<IpAddr>,
        policy: &xshield_core::SitePolicyConfig,
    ) -> bool {
        let Some(source) = source else {
            return false;
        };
        let now = Instant::now();
        // A keyed hash of (site, prefix); a 64-bit collision would merely make
        // two sources share a bucket, and the random key makes one unforgeable.
        let key = self.hasher.hash_one((site_id, meter_address(source)));
        let shard_count = u64::try_from(self.shards.len()).unwrap_or(1);
        let shard = usize::try_from(key % shard_count).unwrap_or(0);
        let rate = f64::from(policy.limits.requests_per_second);
        let burst = f64::from(policy.limits.burst);
        let mut shard = self.shards[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = shard.slot(key, self.slots_per_shard, burst, now);
        let elapsed = now.duration_since(slot.updated).as_secs_f64();
        slot.tokens = (slot.tokens + elapsed * rate).min(burst);
        slot.updated = now;
        if slot.tokens < 1.0 {
            return false;
        }
        slot.tokens -= 1.0;
        true
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().map_or(0, |shard| shard.slots.len()))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use xshield_core::SitePolicyConfig;

    fn policy(requests_per_second: u32, burst: u32) -> SitePolicyConfig {
        let mut policy = SitePolicyConfig::default();
        policy.limits.requests_per_second = requests_per_second;
        policy.limits.burst = burst;
        policy
    }

    fn source(number: u32) -> IpAddr {
        IpAddr::from(number.to_be_bytes())
    }

    // Reviewer reproduction: once 65,536 distinct sources were tracked, every
    // new source was denied (0 of 200 allowed) and each denial walked the whole
    // table under the global lock.
    #[test]
    fn a_full_table_never_denies_a_legitimate_new_source() {
        let limiter = SiteRateLimiter::new();
        let policy = policy(10, 20);
        for number in 0..70_000 {
            assert!(
                limiter.allow("site_a", Some(source(number)), &policy),
                "source {number} must get its own bucket"
            );
        }
        for number in 70_000..70_200 {
            assert!(
                limiter.allow("site_a", Some(source(number)), &policy),
                "new source {number} was denied because the table is full of others"
            );
        }
        assert!(limiter.tracked() <= SHARDS * DEFAULT_SLOTS_PER_SHARD);
    }

    #[test]
    fn eviction_keeps_the_table_at_its_bound_and_each_insert_cheap() {
        let limiter = SiteRateLimiter::with_capacity(2, 8);
        let policy = policy(1, 1);
        let started = Instant::now();
        for number in 0..50_000 {
            assert!(limiter.allow("site_a", Some(source(number)), &policy));
            assert!(limiter.tracked() <= 16);
        }
        assert_eq!(limiter.tracked(), 16);
        // 50,000 evicting inserts into a 16-slot table finish in far less than a
        // second even in a debug build; a full-table scan per insert would not
        // scale like this once the table is large. This is a coarse bound only.
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_source_is_limited_to_its_burst_and_refills() {
        let limiter = SiteRateLimiter::new();
        let policy = policy(1_000, 3);
        let source = Some(source(1));
        let allowed = (0..5)
            .filter(|_| limiter.allow("site_a", source, &policy))
            .count();
        assert!((3..5).contains(&allowed), "{allowed}");
        std::thread::sleep(Duration::from_millis(20));
        assert!(limiter.allow("site_a", source, &policy), "tokens refill");
        // Different sites and different sources have separate budgets.
        assert!(limiter.allow("site_b", source, &policy));
        assert!(limiter.allow("site_a", Some(self::source(2)), &policy));
        // A source that cannot be identified is refused.
        assert!(!limiter.allow("site_a", None, &policy));
    }

    #[test]
    fn clock_keeps_a_busy_source_and_evicts_quiet_ones() {
        // One shard of four slots: the source that keeps being referenced
        // survives a long stream of one-off sources.
        let limiter = SiteRateLimiter::with_capacity(1, 4);
        let policy = policy(1, 2);
        let busy = Some(source(1));
        let mut denied_after_burst = 0;
        for number in 100..140 {
            limiter.allow("site_a", busy, &policy);
            limiter.allow("site_a", Some(source(number)), &policy);
            if !limiter.allow("site_a", busy, &policy) {
                denied_after_burst += 1;
            }
        }
        assert!(
            denied_after_burst > 30,
            "the referenced bucket must not be evicted and reset: {denied_after_burst}"
        );
    }

    #[test]
    fn ipv6_sources_are_metered_per_prefix() {
        let limiter = SiteRateLimiter::new();
        let policy = policy(1, 2);
        let host = |last: u16| -> Option<IpAddr> {
            Some(format!("2001:db8:1:2::{last:x}").parse().unwrap())
        };
        let allowed = (1..=6)
            .filter(|last| limiter.allow("site_a", host(*last), &policy))
            .count();
        assert!(
            allowed <= 3,
            "addresses in one /64 share a budget: {allowed}"
        );
        let other_prefix: Option<IpAddr> = Some("2001:db8:1:3::1".parse().unwrap());
        assert!(limiter.allow("site_a", other_prefix, &policy));
    }
}
