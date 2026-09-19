//! Runs one explicitly approved offline evaluation; stdout contains evidence references only.

use std::{env, path::PathBuf};
use tokio::sync::oneshot;

async fn run() -> Result<bool, &'static str> {
    let mut args = env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--approved-input")) {
        return Err("MODEL_CONFIG_INVALID");
    }
    let input = PathBuf::from(args.next().ok_or("MODEL_CONFIG_INVALID")?);
    if args.next().is_some() {
        return Err("MODEL_CONFIG_INVALID");
    }
    let (sender, mut cancel) = oneshot::channel();
    let evaluation = xshield_worker::model_eval::evaluate_file(&input, &mut cancel);
    tokio::pin!(evaluation);
    let report = tokio::select! {
        report = &mut evaluation => report?,
        signal = tokio::signal::ctrl_c() => {
            let _ = sender.send(());
            let report = evaluation.await?;
            signal.map_err(|_| "MODEL_SIGNAL_UNAVAILABLE")?;
            report
        }
    };
    println!(
        "{}",
        serde_json::to_string(&report).map_err(|_| "MODEL_RECEIPT_UNAVAILABLE")?
    );
    Ok(report.status == "success")
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(reason) => {
            eprintln!("{reason}; usage: xshield-model-eval --approved-input PRIVATE_JSON_FILE");
            std::process::exit(1);
        }
    }
}
