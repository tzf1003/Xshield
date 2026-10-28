//! `xshield-build`: see [`xshield_control::build_cli`].

use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome =
        xshield_control::build_cli::run(&args, std::env::var("XSHIELD_API_KEY").ok()).await;
    if !outcome.stdout.is_empty() {
        println!("{}", outcome.stdout);
    }
    if !outcome.stderr.is_empty() {
        eprintln!("xshield-build: {}", outcome.stderr);
    }
    ExitCode::from(outcome.code)
}
