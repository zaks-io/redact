/// Compare the complete approved output shape, including permitted metadata.
/// Values are caller-controlled synthetic data; no implementation renderer is used.
pub fn matches_record(
    name: &str,
    raw_value: &str,
    state: &str,
    fingerprint: Option<&str>,
    text: &str,
    json: &str,
) -> bool {
    let disclosed = match state {
        "visible" | "empty" => Some(raw_value),
        _ => None,
    };
    let expected_json = serde_json::json!({
        "schema_version": 1,
        "records": [{
            "source": {"kind": "environment"},
            "name": name,
            "state": state,
            "value": disclosed,
            "fingerprint": fingerprint,
        }],
    });
    let actual: Result<serde_json::Value, _> = serde_json::from_str(json);
    if actual.ok().as_ref() != Some(&expected_json) {
        return false;
    }
    let rendered_value = match state {
        "redacted" => format!("[REDACTED sha256={}]", fingerprint.unwrap()),
        "empty" => "[EMPTY]".to_owned(),
        "missing" => "[UNSET]".to_owned(),
        "visible" => serde_json::to_string(raw_value).unwrap(),
        _ => return false,
    };
    let expected_text = format!(
        "\"env\"\t{}\t{rendered_value}\n",
        serde_json::to_string(name).unwrap(),
    );
    text == expected_text
}
