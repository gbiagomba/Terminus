use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub scan_id: String,
    pub url: String,
    pub host: String,
    pub scheme: String,
    pub port: u16,
    pub method: String,
    pub exploit_family: Option<String>,
    pub payload_location: Option<String>,
    pub payload_value: Option<String>,
    pub baseline_status: Option<u16>,
    pub variant_status: u16,
    pub baseline_headers_hash: Option<String>,
    pub variant_headers_hash: Option<String>,
    pub baseline_body_hash: Option<String>,
    pub variant_body_hash: Option<String>,
    pub baseline_content_length: Option<usize>,
    pub variant_content_length: Option<usize>,
    pub body_markers: Vec<String>,
    pub reflected_markers: Vec<String>,
    pub environment_markers: Vec<String>,
    pub auth_markers: Vec<String>,
    pub redirect_location: Option<String>,
    pub confidence_seed: f32,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisRecord {
    pub id: String,
    pub family: String,
    pub statement: String,
    pub supporting_evidence_ids: Vec<String>,
    pub contradicting_evidence_ids: Vec<String>,
    pub confidence_seed: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningTask {
    pub mode: String,
    pub objective: String,
    pub evidence: Vec<EvidenceRecord>,
    pub hypotheses: Vec<HypothesisRecord>,
    pub max_findings: usize,
    pub confidence_threshold: f32,
    pub include_raw_snippets: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningResult {
    pub findings: Vec<ReasonedFinding>,
    pub recommended_requests: Vec<RecommendedRequest>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasonedFinding {
    pub title: String,
    pub rationale: String,
    pub confidence: f32,
    pub severity: String,
    pub evidence_ids: Vec<String>,
    pub likely_true_positive: bool,
    pub next_validation_goal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedRequest {
    pub purpose: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasoning_result_roundtrip() {
        let result = ReasoningResult {
            findings: vec![ReasonedFinding {
                title: "Test".to_string(),
                rationale: "Because".to_string(),
                confidence: 0.7,
                severity: "medium".to_string(),
                evidence_ids: vec!["1".to_string()],
                likely_true_positive: true,
                next_validation_goal: Some("Validate".to_string()),
            }],
            recommended_requests: vec![RecommendedRequest {
                purpose: "Check".to_string(),
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                headers: Vec::new(),
                body: None,
            }],
            notes: vec!["note".to_string()],
        };

        let json = serde_json::to_string(&result).unwrap();
        let decoded: ReasoningResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.findings.len(), 1);
    }
}
