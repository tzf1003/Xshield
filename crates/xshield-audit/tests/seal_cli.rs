use std::{fs, process::Command};
use uuid::Uuid;
use xshield_audit::{JournalKey, JournalLimits, JournalRecord, LocalJournal};
use xshield_core::domain::EventId;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const JOURNAL_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SEAL_KEY: &str = "3333333333333333333333333333333333333333333333333333333333333333";

#[test]
fn seals_a_rotated_segment_while_the_writer_is_active() {
    let root = std::env::temp_dir().join(format!("xshield-seal-cli-{}", Uuid::now_v7()));
    let journal_directory = root.join("journal");
    let manifest_directory = root.join("manifests");
    fs::create_dir_all(&manifest_directory).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&manifest_directory, fs::Permissions::from_mode(0o700)).unwrap();

    let (mut journal, _) = LocalJournal::open(
        &journal_directory,
        "journal-key-r1",
        JournalKey::from_hex(JOURNAL_KEY).unwrap(),
        JournalLimits::new(1024 * 1024, 768 * 1024, 1).unwrap(),
    )
    .unwrap();
    let event = EventId::parse("ev_018f2a3b-4c5d-7000-8000-000000000001").unwrap();
    journal
        .append_batch(&[JournalRecord {
            event_id: &event,
            plaintext: b"cli sealing event",
        }])
        .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_xshield-audit-seal"))
        .arg(&journal_directory)
        .arg(&manifest_directory)
        .env("XSHIELD_JOURNAL_KEY_ID", "journal-key-r1")
        .env("XSHIELD_JOURNAL_KEY_HEX", JOURNAL_KEY)
        .env("XSHIELD_SEAL_KEY_ID", "seal-key-r1")
        .env("XSHIELD_SEAL_KEY_HEX", SEAL_KEY)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"1\n");
    assert!(output.stderr.is_empty());
    assert_eq!(fs::read_dir(&manifest_directory).unwrap().count(), 1);

    drop(journal);
    fs::remove_dir_all(root).unwrap();
}
