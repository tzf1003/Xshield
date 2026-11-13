//! Xshield control-plane executable.
//!
//! Normally runs the HTTP server (see [`xshield_control::router`]). Invoked
//! as `xshield-control hash-password`, it instead reads one line from stdin
//! (the plaintext admin password) and prints the `pbkdf2-sha256$...` value
//! for `XSHIELD_ADMIN_PASSWORD_HASH`, then exits.
//!
//! Before it serves, the server applies the pending schema migrations
//! (docs/04 section 4.2) and exits when one fails.
//!
//! Environment: `XSHIELD_DATABASE_URL` and `XSHIELD_ADMIN_PASSWORD_HASH` are
//! required. `XSHIELD_CONTROL_LISTEN` defaults to `127.0.0.1:8081`.
//! `XSHIELD_CONTROL_CONSOLE_ORIGIN` enables CORS for a console served from
//! another origin during development. The console itself is embedded in the
//! binary at build time and needs no setting. `XSHIELD_CONTROL_PLAIN_HTTP=true`
//! drops `Secure` from the administrator cookie, for a console reached over
//! plain `http://` on a network that is already encrypted (docs/03 section 3.3).
//! `XSHIELD_CONTROL_TRUSTED_PROXIES` lists the reverse proxies in front of the
//! console, so failed sign-ins are counted per client and not per proxy.
//! `XSHIELD_CONTEXT_KEY_HEX`, the same secret the gateways read, lets the model
//! page save API keys; without it those keys cannot be saved.

use std::{env, error::Error, io::Read as _, net::SocketAddr};

use sqlx::postgres::PgPoolOptions;
use xshield_control::{
    ControlState, TrustedProxies, hash_password, router, run_maintenance, run_migrations,
};
use xshield_core::hex::decode_hex;
use xshield_postgres::key_seal::KeySealer;

const DEFAULT_LISTEN: &str = "127.0.0.1:8081";

fn run_hash_password_cli() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let password = input.trim_end_matches(['\n', '\r']);
    println!("{}", hash_password(password)?);
    Ok(())
}

/// The sealer of the model keys, from the context secret when the deployment sets one.
/// Without it the model page can still show the saved settings, but not save a key.
fn context_sealer() -> Result<Option<KeySealer>, Box<dyn Error>> {
    let Ok(text) = env::var("XSHIELD_CONTEXT_KEY_HEX") else {
        return Ok(None);
    };
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let secret = decode_hex(text)
        .filter(|bytes| bytes.len() >= 32)
        .ok_or("XSHIELD_CONTEXT_KEY_HEX must be at least 64 hex digits")?;
    let sealer = KeySealer::from_context_secret(&secret)
        .map_err(|error| format!("XSHIELD_CONTEXT_KEY_HEX: {error:?}"))?;
    Ok(Some(sealer))
}

async fn run_server() -> Result<(), Box<dyn Error>> {
    let database_url = env::var("XSHIELD_DATABASE_URL")?;
    let listen: SocketAddr = env::var("XSHIELD_CONTROL_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN.to_owned())
        .parse()?;
    let admin_password_hash = env::var("XSHIELD_ADMIN_PASSWORD_HASH")
        .map_err(|_| "XSHIELD_ADMIN_PASSWORD_HASH is required")?;
    let console_origin = env::var("XSHIELD_CONTROL_CONSOLE_ORIGIN").ok();
    let plain_http = env::var("XSHIELD_CONTROL_PLAIN_HTTP")
        .is_ok_and(|value| matches!(value.trim(), "1" | "true"));
    if plain_http {
        eprintln!(
            "xshield-control: XSHIELD_CONTROL_PLAIN_HTTP is set, so the administrator cookie is sent without Secure; serve the console only over an encrypted network"
        );
    }

    let trusted_proxies =
        TrustedProxies::parse(&env::var("XSHIELD_CONTROL_TRUSTED_PROXIES").unwrap_or_default())
            .map_err(|item| {
                format!(
                    "XSHIELD_CONTROL_TRUSTED_PROXIES: {item:?} is not an address or a CIDR network"
                )
            })?;

    let pool = PgPoolOptions::new().connect(&database_url).await?;
    run_migrations(&pool).await.map_err(|error| {
        format!(
            "database migration failed: {error} (docs/04 section 4.2 covers a database created before start-up migrations)"
        )
    })?;
    let key_sealer = context_sealer()?;
    let state = ControlState::new(
        pool,
        admin_password_hash,
        console_origin,
        plain_http,
        key_sealer,
        trusted_proxies,
    )
    .map_err(|error| error.to_string())?;

    tokio::spawn(run_maintenance(state.clone()));

    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
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
