use anyhow::{Context, Result};
use clap::ArgMatches;
use async_trait::async_trait;

pub mod correlate;
pub mod extract;
pub mod provider;
pub mod prompts;
pub mod rig_engine;
pub mod types;

use crate::ai::provider::ProviderConfig;
use crate::ai::rig_engine::RigReasoningEngine;
use crate::ai::types::{ReasoningResult, ReasoningTask};
use crate::storage::sqlite::output_ai_assessment;

#[async_trait]
pub trait ReasoningEngine {
    async fn run(&self, task: ReasoningTask) -> Result<ReasoningResult>;
}

pub async fn run_ai(matches: &ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some((mode, sub)) => run_mode(mode, sub).await,
        None => {
            eprintln!("AI mode required (prioritize, cluster, diff, validate, campaign)");
            Ok(())
        }
    }
}

async fn run_mode(mode: &str, matches: &ArgMatches) -> Result<()> {
    let db_path = matches.get_one::<String>("db").context("db is required")?;
    let provider = matches.get_one::<String>("provider").map(|s| s.as_str()).unwrap_or("openai");
    let model = matches.get_one::<String>("model").map(|s| s.as_str()).unwrap_or("gpt-4");
    let base_url = matches.get_one::<String>("base-url").cloned();
    let max_findings = matches.get_one::<String>("max-findings").and_then(|s| s.parse().ok()).unwrap_or(10);
    let confidence_threshold = matches.get_one::<String>("confidence-threshold").and_then(|s| s.parse().ok()).unwrap_or(0.3);
    let include_raw = matches.get_flag("include-raw");

    let evidence = extract::load_evidence(db_path, 100)?;
    let hypotheses = correlate::build_hypotheses(&evidence);

    let task = ReasoningTask {
        mode: mode.to_string(),
        objective: format!("{} analysis", mode),
        evidence,
        hypotheses,
        max_findings,
        confidence_threshold,
        include_raw_snippets: include_raw,
    };

    let config = ProviderConfig::from_args(provider, model, base_url)?;
    let engine = RigReasoningEngine::new(config.clone());
    let result = engine.run(task.clone()).await?;

    output_result(&result);
    output_ai_assessment(db_path, provider, model, &result)?;

    Ok(())
}

fn output_result(result: &ReasoningResult) {
    match serde_json::to_string_pretty(result) {
        Ok(json) => println!("{}", json),
        Err(_) => println!("Failed to serialize AI result"),
    }
}
