use anyhow::Result;

#[derive(Debug, Clone)]
pub enum ProviderKind {
    OpenAi,
    OpenAiCompatible,
    Anthropic,
    Gemini,
    Cohere,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub kind: ProviderKind,
    pub model: String,
    pub base_url: Option<String>,
    pub api_key_env: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
}

impl ProviderConfig {
    pub fn from_args(kind: &str, model: &str, base_url: Option<String>) -> Result<Self> {
        let (kind, api_key_env, default_base_url) = match kind {
            "openai" => (ProviderKind::OpenAi, Some("OPENAI_API_KEY"), None),
            "openai-compatible" => (ProviderKind::OpenAiCompatible, Some("OPENAI_API_KEY"), None),
            "anthropic" => (ProviderKind::Anthropic, Some("ANTHROPIC_API_KEY"), None),
            "gemini" => (ProviderKind::Gemini, Some("GEMINI_API_KEY"), None),
            "cohere" => (ProviderKind::Cohere, Some("COHERE_API_KEY"), None),
            "groq" => (ProviderKind::OpenAiCompatible, Some("GROQ_API_KEY"), Some("https://api.groq.com/openai/v1".to_string())),
            "ollama" => (ProviderKind::OpenAiCompatible, None, Some("http://localhost:11434/v1".to_string())),
            _ => (ProviderKind::OpenAi, Some("OPENAI_API_KEY"), None),
        };

        Ok(Self {
            kind,
            model: model.to_string(),
            base_url: base_url.or(default_base_url),
            api_key_env: api_key_env.map(|v| v.to_string()),
            temperature: None,
            max_tokens: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_provider_kinds() {
        let config = ProviderConfig::from_args("openai", "gpt-4", None).unwrap();
        assert!(matches!(config.kind, ProviderKind::OpenAi));

        let config = ProviderConfig::from_args("openai-compatible", "local", None).unwrap();
        assert!(matches!(config.kind, ProviderKind::OpenAiCompatible));

        let config = ProviderConfig::from_args("anthropic", "claude", None).unwrap();
        assert!(matches!(config.kind, ProviderKind::Anthropic));

        let config = ProviderConfig::from_args("gemini", "gemini-pro", None).unwrap();
        assert!(matches!(config.kind, ProviderKind::Gemini));

        let config = ProviderConfig::from_args("cohere", "command-r", None).unwrap();
        assert!(matches!(config.kind, ProviderKind::Cohere));

        let config = ProviderConfig::from_args("groq", "llama", None).unwrap();
        assert!(matches!(config.kind, ProviderKind::OpenAiCompatible));
        assert!(config.base_url.as_deref().is_some_and(|u| u.contains("groq")));

        let config = ProviderConfig::from_args("ollama", "llama3", None).unwrap();
        assert!(matches!(config.kind, ProviderKind::OpenAiCompatible));
        assert_eq!(config.base_url.as_deref(), Some("http://localhost:11434/v1"));
    }
}
