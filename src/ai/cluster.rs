use crate::ai::types::ReasoningTask;

pub fn apply(task: &mut ReasoningTask) {
    task.objective = "Cluster related findings by host, endpoint, and exploit family.".to_string();
}
