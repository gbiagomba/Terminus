use crate::ai::types::{EvidenceRecord, HypothesisRecord};

pub fn build_hypotheses(evidence: &[EvidenceRecord]) -> Vec<HypothesisRecord> {
    let mut hypotheses = Vec::new();
    for (idx, record) in evidence.iter().enumerate() {
        if record.variant_status >= 500 {
            hypotheses.push(HypothesisRecord {
                id: format!("hypo-{}", idx),
                family: "stability".to_string(),
                statement: format!("Endpoint {} returned 5xx and may be unstable", record.url),
                supporting_evidence_ids: vec![record.url.clone()],
                contradicting_evidence_ids: Vec::new(),
                confidence_seed: 0.4,
            });
        }
    }
    hypotheses
}
