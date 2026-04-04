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
        let kind = match kind {
            "openai" => ProviderKind::OpenAi,
            "openai-compatible" => ProviderKind::OpenAiCompatible,
            "anthropic" => ProviderKind::Anthropic,
            "gemini" => ProviderKind::Gemini,
            "cohere" => ProviderKind::Cohere,
            _ => ProviderKind::OpenAi,
        };

        Ok(Self {
            kind,
            model: model.to_string(),
            base_url,
            api_key_env: None,
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
    }
}
