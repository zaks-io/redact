/// Canary checks include escaped whole values and fixed unique fragments.
/// Callers supply synthetic values whose fragments cannot occur in metadata.
pub fn leaks_canary(output: &str, value: &str) -> bool {
    if output.contains(value) {
        return true;
    }
    let escaped = serde_json::to_string(value).unwrap();
    if output.contains(&escaped[1..escaped.len() - 1]) {
        return true;
    }
    value.len() >= 32
        && (output.contains("SYNTHETIC_FUZZ_CANARY_")
            || output.contains("CREDENTIAL_CANARY_0123456789"))
}
