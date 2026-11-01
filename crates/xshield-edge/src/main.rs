//! `xshield-edge`: the v4 data plane process.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use xshield_edge::proxy::EdgeProxy;
use xshield_edge::server::build_server;
use xshield_edge::settings::Settings;
use xshield_edge::sink::{DecisionSink, QUEUE_CAPACITY, now_millis, write_postgres, write_stdout};
use xshield_edge::sites::SiteTable;
use xshield_edge::source::{SiteLoader, SiteSource};
use xshield_edge::status::{self, Instance};
use xshield_judge::context::ContextKey;
use xshield_judge::engine::Judge;
use xshield_judge::jev::JevClient;

fn run() -> Result<(), Box<dyn Error>> {
    let settings = Settings::from_environment()?;
    let jev = JevClient::from_environment()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?;

    let table = Arc::new(SiteTable::new());
    let (sink, rx) = DecisionSink::channel(QUEUE_CAPACITY);
    let counters = sink.counters();
    let judge = Arc::new(Judge::new(ContextKey::new(settings.context_key), jev));
    let edge = status::edge_name();
    let instance = Instance {
        edge: edge.clone(),
        started_at_millis: i64::try_from(now_millis()).unwrap_or(i64::MAX),
        listen: settings
            .ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
        tls: settings.tls.is_some(),
    };
    let source = if let Some(url) = &settings.database_url {
        let pool = runtime.block_on(
            PgPoolOptions::new()
                .max_connections(4)
                .acquire_timeout(Duration::from_secs(5))
                .connect(url),
        )?;
        runtime.spawn(write_postgres(pool.clone(), rx, counters.clone()));
        runtime.spawn(status::run(
            pool.clone(),
            Arc::clone(&judge),
            Arc::clone(&table),
            counters,
            instance,
        ));
        SiteSource::Postgres(pool)
    } else if let Some(path) = &settings.sites_file {
        runtime.spawn(write_stdout(rx, counters));
        SiteSource::File(path.clone())
    } else {
        return Err("no site source".into());
    };
    let mut loader = SiteLoader::new(source, Arc::clone(&table));
    // Starting with an unreadable source would serve nothing; fail instead.
    runtime.block_on(loader.refresh())?;
    eprintln!("xshield-edge: {} host name(s) routed", table.len());
    runtime.spawn(loader.run());

    let addresses: Vec<String> = settings
        .ports
        .iter()
        .map(|port| format!("0.0.0.0:{port}"))
        .collect();
    let server = build_server(
        EdgeProxy::new(Arc::clone(&table), judge, sink, edge),
        &addresses,
        settings.tls.as_ref(),
        None,
    )?;
    // The background tasks (site refresh, log writer, heartbeat) live on this runtime.
    let _runtime = runtime;
    server.run_forever()
}

fn main() {
    if let Err(error) = run() {
        eprintln!("xshield-edge: {error}");
        std::process::exit(1);
    }
}
