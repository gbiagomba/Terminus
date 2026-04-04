use crate::ai::types::ReasoningTask;

pub fn apply(task: &mut ReasoningTask) {
    task.objective = "Explain meaningful deltas between scans and rank changes by operational impact.".to_string();
}
