use anyhow::Result;
use clap::ArgMatches;

pub mod paths;
pub mod subdomains;

pub async fn run_enum(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("subdomains", sub)) => subdomains::run(sub).await,
        Some(("paths", sub)) => paths::run(sub).await,
        _ => {
            eprintln!("Enum requires a subcommand: subdomains or paths");
            Ok(())
        }
    }
}
