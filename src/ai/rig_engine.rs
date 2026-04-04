use anyhow::{Context, Result};
use rig::{client::{ProviderClient, CompletionClient}, completion::Prompt, providers::{openai, anthropic, cohere, gemini}};

use crate::ai::ReasoningEngine;
use crate::ai::provider::{ProviderConfig, ProviderKind};
use crate::ai::types::{ReasoningResult, ReasoningTask};

pub struct RigReasoningEngine {
    config: ProviderConfig,
}

impl RigReasoningEngine {
    pub fn new(config: ProviderConfig) -> Self {
        Self { config }
    }
}

#[async_trait::async_trait]
impl ReasoningEngine for RigReasoningEngine {
    async fn run(&self, task: ReasoningTask) -> Result<ReasoningResult> {
        let prompt = crate::ai::prompts::build_prompt(&task);

        let response: String = match self.config.kind {
            ProviderKind::OpenAi | ProviderKind::OpenAiCompatible => {
                if let Some(base_url) = &self.config.base_url {
                    std::env::set_var("OPENAI_BASE_URL", base_url);
                }
                let client = <openai::Client as ProviderClient>::from_env();
                let agent = client.agent(self.config.model.clone()).build();
                agent.prompt(prompt.clone()).await?
            }
            ProviderKind::Anthropic => {
                let api_key = std::env::var("ANTHROPIC_API_KEY")
                    .context("ANTHROPIC_API_KEY not set")?;
                let client = anthropic::Client::new(api_key)?;
                let agent = client.agent(self.config.model.clone()).build();
                agent.prompt(prompt.clone()).await?
            }
            ProviderKind::Gemini => {
                let api_key = std::env::var("GEMINI_API_KEY")
                    .context("GEMINI_API_KEY not set")?;
                let client = gemini::Client::new(api_key)?;
                let agent = client.agent(self.config.model.clone()).build();
                agent.prompt(prompt.clone()).await?
            }
            ProviderKind::Cohere => {
                let api_key = std::env::var("COHERE_API_KEY")
                    .context("COHERE_API_KEY not set")?;
                let client = cohere::Client::new(api_key)?;
                let agent = client.agent(self.config.model.clone()).build();
                agent.prompt(prompt.clone()).await?
            }
        };

        let parsed: ReasoningResult = serde_json::from_str(&response)
            .context("Failed to parse AI response as ReasoningResult JSON")?;
        Ok(parsed)
    }
}
