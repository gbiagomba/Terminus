use crate::ai::types::ReasoningTask;

pub fn build_prompt(task: &ReasoningTask) -> String {
    let task_json = serde_json::to_string_pretty(task).unwrap_or_else(|_| "{}".to_string());

    format!(
        "You are a security analysis engine. Use the provided JSON task to produce a JSON ReasoningResult.\n\nTask:\n{}\n\nReturn only valid JSON that matches the ReasoningResult schema: {{ findings: [], recommended_requests: [], notes: [] }}",
        task_json
    )
}
