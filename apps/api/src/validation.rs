use crate::error::ApiError;

pub fn slugify(input: &str, limit: usize) -> String {
    let mut result = String::new();
    for character in input.trim().to_ascii_lowercase().chars() {
        if character.is_ascii_alphanumeric() {
            result.push(character);
        } else if (character == '-' || character == '_' || character.is_ascii_whitespace())
            && !result.is_empty() && !result.ends_with('-') {
            result.push('-');
        }
        if result.len() >= limit { break; }
    }
    result.trim_end_matches('-').to_owned()
}

pub fn check_text(value: &str, min: usize, max: usize, error: &'static str) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.chars().count() < min || trimmed.chars().count() > max || trimmed.chars().any(char::is_control) {
        return Err(ApiError::bad_request(error));
    }
    Ok(trimmed.to_owned())
}

pub fn valid_transition(from: &str, to: &str) -> bool {
    match from {
        "pending" => matches!(to, "running" | "succeeded" | "failed" | "cancelled"),
        "running" => matches!(to, "succeeded" | "failed" | "cancelled"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slug_normalization() {
        assert_eq!(slugify("  My API -- Production  ", 80), "my-api-production");
        assert_eq!(slugify("Café 🚀 platform", 80), "caf-platform");
    }
    #[test]
    fn terminal_deployments_cannot_change() {
        assert!(valid_transition("pending", "running"));
        assert!(valid_transition("running", "succeeded"));
        assert!(!valid_transition("succeeded", "running"));
        assert!(!valid_transition("running", "running"));
    }
    #[test]
    fn content_validation() {
        assert!(check_text("  hello  ", 2, 20, "invalid").is_ok());
        assert!(check_text("\n", 1, 10, "invalid").is_err());
    }
}
