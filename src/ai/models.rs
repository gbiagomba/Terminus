use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::Value;

use crate::ai::provider::{ProviderConfig, ProviderKind};

pub async fn list_models(provider: &str, base_url: Option<String>) -> Result<()> {
    let config = ProviderConfig::from_args(provider, "unused", base_url)?;
    match config.kind {
        ProviderKind::OpenAi | ProviderKind::OpenAiCompatible => {
            if config.base_url.as_deref() == Some("http://localhost:11434/v1") {
                list_ollama_models().await
            } else {
                list_openai_models(&config).await
            }
        }
        ProviderKind::Gemini => list_gemini_models(&config).await,
        ProviderKind::Cohere | ProviderKind::Anthropic => {
            println!("Model discovery not implemented for provider: {}", provider);
            Ok(())
        }
    }
}

async fn list_openai_models(config: &ProviderConfig) -> Result<()> {
    let base = config.base_url.clone().unwrap_or_else(|| "https://api.openai.com/v1".to_string());
    let url = format!("{}/models", base.trim_end_matches('/'));
    let key = config.api_key_env.clone().unwrap_or_else(|| "OPENAI_API_KEY".to_string());
    let api_key = std::env::var(&key)
        .with_context(|| format!("{} not set", key))?;

    let client = Client::new();
    let response = client
        .get(url)
        .bearer_auth(api_key)
        .send()
        .await
        .context("Failed to query models endpoint")?;

    let payload: Value = response.json().await?;
    let data = payload.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for item in data {
        if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
            println!("{}", id);
        }
    }

    Ok(())
}

async fn list_gemini_models(_config: &ProviderConfig) -> Result<()> {
    let api_key = std::env::var("GEMINI_API_KEY")
        .context("GEMINI_API_KEY not set")?;
    let url = format!("https://generativelanguage.googleapis.com/v1beta/models?key={}", api_key);
    let client = Client::new();
    let response = client
        .get(url)
        .send()
        .await
        .context("Failed to query Gemini models endpoint")?;

    let payload: Value = response.json().await?;
    let data = payload.get("models").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for item in data {
        if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
            println!("{}", name);
        }
    }

    Ok(())
}

pub async fn list_ollama_models() -> Result<()> {
    let client = Client::new();
    let response = client
        .get("http://localhost:11434/api/tags")
        .send()
        .await
        .context("Failed to query Ollama tags endpoint")?;
    let payload: Value = response.json().await?;
    let data = payload.get("models").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    for item in data {
        if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
            println!("{}", name);
        }
    }
    Ok(())
}
