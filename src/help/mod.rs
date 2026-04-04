use anyhow::Result;
use clap::ArgMatches;

mod manual;

pub fn run_help(matches: &ArgMatches) -> Result<()> {
    let topic = matches.get_one::<String>("topic").map(|s| s.as_str());
    let content = manual::render(topic);
    println!("{}", content);
    Ok(())
}
