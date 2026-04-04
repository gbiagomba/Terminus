use crate::ai::types::ReasoningTask;

pub fn apply(task: &mut ReasoningTask) {
    task.objective = "Propose minimal next requests that reduce uncertainty for top findings.".to_string();
}
