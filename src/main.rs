use anyhow::Result;

mod cli;
mod diff;
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
            diff::run_diff(base, compare)
        }
        Some(("interact", sub)) => {
            let db = sub.get_one::<String>("db").expect("db is required");
            interact::run_interact(db)
        }
        Some(("help", _)) => {
            println!("Terminus manual help is not yet implemented in this phase.");
            Ok(())
        }
        Some(("enum", _)) => {
            println!("Enum subcommand is not yet implemented in this phase.");
            Ok(())
        }
        Some(("ai", _)) => {
            println!("AI subcommand is not yet implemented in this phase.");
            Ok(())
        }
        _ => Ok(()),
    }
}
