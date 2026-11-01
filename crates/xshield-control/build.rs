//! Embeds the built console (`web/console/dist`) into the control binary, so the
//! control plane serves the console from the same origin without reading any
//! file at run time (docs/07-console-architecture.md section 7.2.3).
//!
//! When the console has not been built, the generated table is empty and the
//! control plane answers `/` with 503 until it is built.

use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    let console = manifest_dir.join("../../web/console/dist");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", console.display());

    let mut files = Vec::new();
    collect_files(&console, &console, &mut files);
    files.sort();

    let mut source = String::from("&[\n");
    for (relative, absolute) in &files {
        writeln!(
            source,
            "    ConsoleFile {{ path: {relative:?}, bytes: include_bytes!({absolute:?}) }},"
        )
        .expect("writing to a String cannot fail");
    }
    source.push_str("]\n");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    fs::write(out_dir.join("console_files.rs"), source).expect("write console_files.rs");
}

/// Lists every file under `dir` as (path relative to `root` with `/` separators,
/// absolute path). A missing directory contributes nothing.
fn collect_files(root: &Path, dir: &Path, files: &mut Vec<(String, String)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, files);
        } else if let Ok(relative) = path.strip_prefix(root) {
            files.push((
                relative.to_string_lossy().replace('\\', "/"),
                path.to_string_lossy().into_owned(),
            ));
        }
    }
}
