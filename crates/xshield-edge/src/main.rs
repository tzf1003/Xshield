//! `xshield-edge`: the v4 data plane process.

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use xshield_edge::jev_settings::JevLoader;
use xshield_edge::proxy::EdgeProxy;
use xshield_edge::server::build_server;
use xshield_edge::settings::Settings;
use xshield_edge::sink::{DecisionSink, QUEUE_CAPACITY, now_millis, write_postgres, write_stdout};
use xshield_edge::sites::SiteTable;
use xshield_edge::source::{SiteLoader, SiteSource};
use xshield_edge::status::{self, Instance};
use xshield_judge::context::ContextKey;
use xshield_judge::engine::Judge;
use xshield_judge::jev::environment_settings;
use xshield_judge::slot::JevSlot;
use xshield_postgres::key_seal::KeySealer;

fn run() -> Result<(), Box<dyn Error>> {
    let settings = Settings::from_environment()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()?;

    // The judge calls through a slot that the settings saved in the console can
    // replace while the gateway runs (docs/03 section 3.3). Nothing loaded is not a
    // start-up error: judgements report JEV_NOT_CONFIGURED until a key is saved in
    // the console or set in the environment.
    let sealer = KeySealer::from_context_secret(&settings.context_key)
        .map_err(|error| format!("XSHIELD_CONTEXT_KEY_HEX: {error:?}"))?;
    let slot = Arc::new(JevSlot::new());
    let jev = Arc::new(JevLoader::new(
        Arc::clone(&slot),
        environment_settings(),
        sealer,
    ));
    jev.start();

    let table = Arc::new(SiteTable::new());
    let (sink, rx) = DecisionSink::channel(QUEUE_CAPACITY);
    let counters = sink.counters();
    let judge = Arc::new(Judge::new(
        ContextKey::new(settings.context_key),
        Arc::clone(&slot),
    ));
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
        // The saved settings apply before the first judgement when they can be read.
        runtime.block_on(jev.refresh(&pool));
        runtime.spawn(Arc::clone(&jev).run(pool.clone()));
        runtime.spawn(write_postgres(pool.clone(), rx, counters.clone()));
        runtime.spawn(status::run(
            pool.clone(),
            Arc::clone(&judge),
            Arc::clone(&table),
            counters,
            instance,
            Arc::clone(&jev),
        ));
        SiteSource::Postgres(pool)
    } else if let Some(path) = &settings.sites_file {
        runtime.spawn(write_stdout(rx, counters));
        SiteSource::File(path.clone())
    } else {
        return Err("no site source".into());
    };
    if jev.report().source.is_none() {
        eprintln!(
            "xshield-edge: no Jev key is loaded; judgements report JEV_NOT_CONFIGURED \
             until one is saved in the console or set in the environment"
        );
    }
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
