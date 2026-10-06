//! Prints the management access audit journal as one JSON event per line.
//!
//! Purpose: lets `scripts/test_oidc_login.py` read back the events a real
//! control process wrote. The journal is AES-256-GCM encrypted, so a script
//! cannot read it without the journal key. This is a development and test
//! tool, not a shipped binary: it is a Cargo example and is not built into the
//! container images.
//!
//! Usage: `dump_access_audit CONTROL_AUDIT_DIRECTORY`, with
//! `XSHIELD_CONTROL_AUDIT_KEY_ID` and `XSHIELD_CONTROL_AUDIT_KEY_HEX` set.
//!
//! Invariants: read-only; every record is authenticated before it is printed;
//! a wrong key, tampered segment or unsafe directory fails the whole read
//! instead of printing a partial result. Key material is never printed.

use std::{env, error::Error, path::PathBuf};
use xshield_audit::{JournalError, JournalKey, LocalJournal};
use zeroize::Zeroizing;

const USAGE: &str = "usage: dump_access_audit CONTROL_AUDIT_DIRECTORY";

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let directory = PathBuf::from(arguments.next().ok_or(USAGE)?);
    if arguments.next().is_some() {
        return Err(USAGE.into());
    }
    let key_id = env::var("XSHIELD_CONTROL_AUDIT_KEY_ID")?;
    let key_hex = Zeroizing::new(env::var("XSHIELD_CONTROL_AUDIT_KEY_HEX")?);
    let key = JournalKey::from_hex(&key_hex)?;
    LocalJournal::visit_committed_records(
        &directory,
        &key_id,
        &key,
        1_000_000,
        1 << 30,
        |record| {
            let text = std::str::from_utf8(record.plaintext())
                .map_err(|_| JournalError::Corrupt("event is not UTF-8"))?;
            println!("{text}");
            Ok(())
        },
    )?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("dump_access_audit failed: {error}");
        std::process::exit(1);
    }
}
