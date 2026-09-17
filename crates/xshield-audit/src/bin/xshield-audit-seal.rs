use std::{env, error::Error, path::PathBuf};
use xshield_audit::{JournalKey, SealSigningKey, seal_closed_segments};
use zeroize::Zeroizing;

fn run() -> Result<usize, Box<dyn Error>> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let journal_directory = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: xshield-audit-seal JOURNAL_DIRECTORY MANIFEST_DIRECTORY")?,
    );
    let manifest_directory = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: xshield-audit-seal JOURNAL_DIRECTORY MANIFEST_DIRECTORY")?,
    );
    if arguments.next().is_some() {
        return Err("usage: xshield-audit-seal JOURNAL_DIRECTORY MANIFEST_DIRECTORY".into());
    }

    let journal_key_id = env::var("XSHIELD_JOURNAL_KEY_ID")?;
    let journal_key_hex = Zeroizing::new(env::var("XSHIELD_JOURNAL_KEY_HEX")?);
    let seal_key_id = env::var("XSHIELD_SEAL_KEY_ID")?;
    let seal_key_hex = Zeroizing::new(env::var("XSHIELD_SEAL_KEY_HEX")?);
    let journal_key = JournalKey::from_hex(&journal_key_hex)?;
    let seal_key = SealSigningKey::from_hex(seal_key_id, &seal_key_hex)?;
    Ok(seal_closed_segments(
        journal_directory,
        manifest_directory,
        &journal_key_id,
        &journal_key,
        &seal_key,
    )?
    .len())
}

fn main() {
    match run() {
        Ok(count) => println!("{count}"),
        Err(error) => {
            eprintln!("xshield audit sealing failed: {error}");
            std::process::exit(1);
        }
    }
}
