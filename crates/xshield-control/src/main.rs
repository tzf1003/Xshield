//! Xshield control-plane executable.
//!
//! Normally runs the HTTP server (see [`xshield_control::router`]). Invoked
//! as `xshield-control hash-password`, it instead reads one line from stdin
//! (the plaintext admin password) and prints the `pbkdf2-sha256$...` value
//! for `XSHIELD_ADMIN_PASSWORD_HASH`, then exits.

use std::{env, error::Error, io::Read as _, net::SocketAddr};

use sqlx::postgres::PgPoolOptions;
use xshield_control::{ControlState, hash_password, router, run_decision_log_retention_loop};

fn run_hash_password_cli() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let password = input.trim_end_matches(['\n', '\r']);
    println!("{}", hash_password(password)?);
    Ok(())
}

async fn run_server() -> Result<(), Box<dyn Error>> {
    let database_url = env::var("XSHIELD_DATABASE_URL")?;
    let listen: SocketAddr = env::var("XSHIELD_CONTROL_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_owned())
        .parse()?;
    let admin_password_hash = env::var("XSHIELD_ADMIN_PASSWORD_HASH")
        .map_err(|_| "XSHIELD_ADMIN_PASSWORD_HASH is required")?;
    let console_origin = env::var("XSHIELD_CONTROL_CONSOLE_ORIGIN").ok();

    let pool = PgPoolOptions::new().connect(&database_url).await?;
    let state = ControlState::new(pool.clone(), admin_password_hash, console_origin)
        .map_err(|error| error.to_string())?;

    tokio::spawn(run_decision_log_retention_loop(pool));

    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let mut arguments = env::args();
    let _program = arguments.next();
    if arguments.next().as_deref() == Some("hash-password") {
        if let Err(error) = run_hash_password_cli() {
            eprintln!("xshield-control hash-password failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(error) = run_server().await {
        eprintln!("xshield-control failed: {error}");
        std::process::exit(1);
    }
}
