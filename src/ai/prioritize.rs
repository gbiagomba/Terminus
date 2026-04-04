use crate::ai::types::ReasoningTask;

pub fn apply(task: &mut ReasoningTask) {
    task.objective = "Prioritize the most likely real findings and the next validation steps.".to_string();
    task.evidence.sort_by(|a, b| b.confidence_seed.partial_cmp(&a.confidence_seed).unwrap_or(std::cmp::Ordering::Equal));
}
