//! Secrets from the environment or from a file named by `<NAME>_FILE`.
//!
//! Orchestrators mount secrets as files (Docker and Kubernetes secrets), which
//! keeps them out of `/proc/<pid>/environ`, `docker inspect` and crash dumps.
//! Every secret the binaries read accepts either `NAME` or `NAME_FILE`, never
//! both: setting both is refused so a stale variable cannot silently win over
//! the mounted file. Errors name the variable, never the value.

use std::fmt;
use std::io::Read as _;

/// Largest secret file read; keys and URLs are far smaller.
pub const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;

/// Why a secret could not be read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretEnvError {
    /// Neither `NAME` nor `NAME_FILE` is set.
    NotSet(String),
    /// Both `NAME` and `NAME_FILE` are set.
    Ambiguous(String),
    /// The variable or `NAME_FILE` path is not valid Unicode.
    NotUnicode(String),
    /// The file named by `NAME_FILE` cannot be read, is too large or is not
    /// UTF-8.
    Unreadable(String),
}

impl fmt::Display for SecretEnvError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSet(name) => write!(formatter, "{name} or {name}_FILE must be set"),
            Self::Ambiguous(name) => {
                write!(formatter, "set only one of {name} and {name}_FILE")
            }
            Self::NotUnicode(name) => write!(formatter, "{name} is not valid Unicode"),
            Self::Unreadable(name) => write!(
                formatter,
                "the file named by {name}_FILE cannot be read as UTF-8 of at most 64 KiB"
            ),
        }
    }
}

impl std::error::Error for SecretEnvError {}

fn lookup(name: &str) -> Result<Option<String>, SecretEnvError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(SecretEnvError::NotUnicode(name.to_owned())),
    }
}

fn read_file(name: &str, path: &str) -> Result<String, SecretEnvError> {
    let unreadable = || SecretEnvError::Unreadable(name.to_owned());
    let file = std::fs::File::open(path).map_err(|_| unreadable())?;
    let mut bytes = Vec::new();
    file.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unreadable())?;
    if bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(unreadable());
    }
    let mut value = String::from_utf8(bytes).map_err(|_| unreadable())?;
    // Editors and `echo` add one line ending; nothing else is trimmed.
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    Ok(value)
}

/// The secret `name`, from the variable itself or from the file named by
/// `name_FILE`; `None` when neither is set.
///
/// # Errors
///
/// [`SecretEnvError`] when both are set or the value cannot be read.
pub fn var_opt(name: &str) -> Result<Option<String>, SecretEnvError> {
    var_opt_from(name, lookup)
}

fn var_opt_from(
    name: &str,
    lookup: impl Fn(&str) -> Result<Option<String>, SecretEnvError>,
) -> Result<Option<String>, SecretEnvError> {
    let file_name = format!("{name}_FILE");
    match (lookup(name)?, lookup(&file_name)?) {
        (Some(_), Some(_)) => Err(SecretEnvError::Ambiguous(name.to_owned())),
        (Some(value), None) => Ok(Some(value)),
        (None, Some(path)) => read_file(name, &path).map(Some),
        (None, None) => Ok(None),
    }
}

/// Like [`var_opt`], but a missing secret is an error.
///
/// # Errors
///
/// [`SecretEnvError::NotSet`] when neither is set, otherwise as [`var_opt`].
pub fn var(name: &str) -> Result<String, SecretEnvError> {
    var_opt(name)?.ok_or_else(|| SecretEnvError::NotSet(name.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn from(
        pairs: &[(&str, &str)],
    ) -> impl Fn(&str) -> Result<Option<String>, SecretEnvError> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        move |name| Ok(map.get(name).cloned())
    }

    fn file(contents: &[u8]) -> std::path::PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "xshield-secret-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn a_secret_comes_from_the_variable_or_its_file() {
        assert_eq!(var_opt_from("S", from(&[])), Ok(None));
        assert_eq!(
            var_opt_from("S", from(&[("S", "abc\n")])),
            Ok(Some("abc\n".to_owned()))
        );
        let path = file(b"0123abcd\r\n");
        let lookup = from(&[("S_FILE", path.to_str().unwrap())]);
        assert_eq!(var_opt_from("S", &lookup), Ok(Some("0123abcd".to_owned())));
        // Only one line ending is removed.
        std::fs::write(&path, b"two\n\n").unwrap();
        assert_eq!(var_opt_from("S", &lookup), Ok(Some("two\n".to_owned())));
        std::fs::remove_file(path).unwrap();
        // The process environment is the default source.
        assert_eq!(
            var("XSHIELD_TEST_SECRET_NEVER_SET"),
            Err(SecretEnvError::NotSet(
                "XSHIELD_TEST_SECRET_NEVER_SET".to_owned()
            ))
        );
    }

    #[test]
    fn ambiguous_or_unreadable_secrets_are_refused_without_their_value() {
        let path = file(b"from-file");
        let error = var_opt_from(
            "S",
            from(&[("S", "from-variable"), ("S_FILE", path.to_str().unwrap())]),
        )
        .unwrap_err();
        assert_eq!(error, SecretEnvError::Ambiguous("S".to_owned()));
        assert!(!error.to_string().contains("from-"));
        let unreadable = |lookup| {
            matches!(
                var_opt_from("S", lookup),
                Err(SecretEnvError::Unreadable(_))
            )
        };
        assert!(unreadable(from(&[(
            "S_FILE",
            "/nonexistent/xshield/secret"
        )])));
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(unreadable(from(&[("S_FILE", path.to_str().unwrap())])));
        let large = usize::try_from(MAX_SECRET_FILE_BYTES).unwrap() + 1;
        std::fs::write(&path, vec![b'a'; large]).unwrap();
        assert!(unreadable(from(&[("S_FILE", path.to_str().unwrap())])));
        std::fs::remove_file(path).unwrap();
    }
}
