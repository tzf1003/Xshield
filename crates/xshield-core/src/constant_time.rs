//! Constant-time equality for secrets: MACs, signatures, tokens, cookies, cursor keys.
//!
//! Purpose: the one comparison every secret check in the workspace goes through.
//! Do not call `openssl::memcmp::eq` directly: it requires equal lengths and
//! **panics** otherwise, and a panic on an attacker-chosen length drops the
//! connection with no audit record and no stable error code (found by driving a
//! real OIDC login, docs/20). `clippy.toml` forbids it.
//!
//! Invariants: unequal lengths are simply "not equal"; the length of a secret is
//! not itself secret in this system (fixed-size random values, fixed-size MACs).
//! For equal lengths the running time does not depend on where the values differ.
//! No I/O, no allocation, no panics on any input.

use subtle::ConstantTimeEq;

/// Whether `left` and `right` hold the same bytes.
///
/// A length mismatch returns `false` without comparing content.
#[must_use]
pub fn eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests {
    use super::eq;

    #[test]
    fn equal_values_match() {
        assert!(eq(b"", b""));
        assert!(eq(b"secret", b"secret"));
        assert!(eq(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn a_difference_anywhere_is_a_mismatch() {
        let base = [7u8; 32];
        for index in 0..base.len() {
            let mut other = base;
            other[index] ^= 1;
            assert!(!eq(&base, &other), "byte {index}");
        }
    }

    #[test]
    fn unequal_lengths_are_a_mismatch_and_never_a_panic() {
        assert!(!eq(b"", b"a"));
        assert!(!eq(b"a", b""));
        assert!(!eq(b"secret", b"secret!"));
        assert!(!eq(&[0u8; 32], &[0u8; 31]));
        // A prefix is not equality.
        assert!(!eq(b"abc", b"abcd"));
    }
}
