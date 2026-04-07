use crate::ai::types::ReasoningTask;

pub fn apply(task: &mut ReasoningTask) {
    task.objective = "Build a staged campaign plan with prioritization, validation, and follow-up requests.".to_string();
}
