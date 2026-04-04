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
                if let Some(api_key_env) = &self.config.api_key_env {
                    if let Ok(key) = std::env::var(api_key_env) {
                        std::env::set_var("OPENAI_API_KEY", key);
                    } else if api_key_env == "GROQ_API_KEY" {
                        return Err(anyhow::anyhow!("GROQ_API_KEY not set"));
                    }
                } else if self.config.base_url.as_deref() == Some("http://localhost:11434/v1") {
                    std::env::set_var("OPENAI_API_KEY", "ollama");
                }

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

        let sanitized = sanitize_json_response(&response);
        let parsed = parse_reasoning_result(&sanitized)
            .context("Failed to parse AI response as ReasoningResult JSON")?;
        Ok(parsed)
    }
}

fn sanitize_json_response(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("```") {
        let mut inner = trimmed.trim_start_matches("```");
        if let Some(pos) = inner.find('\n') {
            inner = &inner[pos + 1..];
        }
        if let Some(end) = inner.rfind("```") {
            inner = &inner[..end];
        }
        return inner.trim().to_string();
    }

    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if end > start {
            return trimmed[start..=end].trim().to_string();
        }
    }

    trimmed.to_string()
}

fn parse_reasoning_result(raw: &str) -> Result<ReasoningResult> {
    if let Ok(result) = serde_json::from_str::<ReasoningResult>(raw) {
        return Ok(result);
    }

    let value: serde_json::Value = serde_json::from_str(raw)?;
    let findings = value.get("findings").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut parsed_findings = Vec::new();
    for item in findings {
        let title = item.get("title").and_then(|v| v.as_str()).unwrap_or("Untitled").to_string();
        let rationale = item.get("rationale").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let confidence = item.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
        let severity = item.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let evidence_ids = item.get("evidence_ids").and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|e| e.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        let likely_true_positive = item.get("likely_true_positive").and_then(|v| v.as_bool()).unwrap_or(false);
        let next_validation_goal = item.get("next_validation_goal").and_then(|v| v.as_str()).map(|s| s.to_string());

        parsed_findings.push(crate::ai::types::ReasonedFinding {
            title,
            rationale,
            confidence,
            severity,
            evidence_ids,
            likely_true_positive,
            next_validation_goal,
        });
    }

    let requests = value.get("recommended_requests").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut parsed_requests = Vec::new();
    for item in requests {
        let purpose = item.get("purpose").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let method = item.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string();
        let url = item.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let headers = item.get("headers").and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().filter_map(|h| {
                    if let Some(pair) = h.as_array() {
                        if pair.len() == 2 {
                            let k = pair[0].as_str()?.to_string();
                            let v = pair[1].as_str()?.to_string();
                            return Some((k, v));
                        }
                    }
                    None
                }).collect()
            })
            .unwrap_or_default();
        let body = item.get("body").and_then(|v| v.as_str()).map(|s| s.to_string());

        parsed_requests.push(crate::ai::types::RecommendedRequest {
            purpose,
            method,
            url,
            headers,
            body,
        });
    }

    let notes = value.get("notes").and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|n| n.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    Ok(ReasoningResult {
        findings: parsed_findings,
        recommended_requests: parsed_requests,
        notes,
    })
}
