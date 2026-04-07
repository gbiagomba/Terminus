use anyhow::Result;

mod cli;
mod diff;
mod r#enum;
mod ai;
mod help;
mod interact;
mod models;
mod output;
mod scan;
mod storage;
mod transport;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();

    match matches.subcommand() {
        Some(("scan", sub)) => scan::run_scan(sub).await,
        Some(("diff", sub)) => {
            let base = sub.get_one::<String>("base").expect("base is required");
            let compare = sub.get_one::<String>("compare").expect("compare is required");
            diff::run_diff(base, compare, sub)
        }
        Some(("interact", sub)) => {
            let db = sub.get_one::<String>("db").expect("db is required");
            let no_tui = sub.get_flag("no-tui");
            interact::run_interact_with_opts(db, no_tui)
        }
        Some(("help", sub)) => help::run_help(sub),
        Some(("enum", sub)) => r#enum::run_enum(sub).await,
        Some(("ai", sub)) => ai::run_ai(sub).await,
        _ => Ok(()),
    }
}
