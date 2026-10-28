//! `xshield-build`: see [`xshield_control::build_cli`].

use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let api_key = match xshield_core::secret_env::var_opt("XSHIELD_API_KEY") {
        Ok(api_key) => api_key,
        Err(error) => {
            eprintln!("xshield-build: {error}");
            return ExitCode::from(1);
        }
    };
    let outcome = xshield_control::build_cli::run(&args, api_key).await;
    if !outcome.stdout.is_empty() {
        println!("{}", outcome.stdout);
    }
    if !outcome.stderr.is_empty() {
        eprintln!("xshield-build: {}", outcome.stderr);
    }
    ExitCode::from(outcome.code)
}
