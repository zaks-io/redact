pub fn format_fixture(data: &[u8]) -> Option<(String, String, i64)> {
    static FIXTURES: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    let fixtures = FIXTURES.get_or_init(|| {
        serde_json::from_str(include_str!("../../tests/fixtures/secret-formats.json")).unwrap()
    });
    let cases = fixtures["cases"].as_array().unwrap();
    let index = data
        .iter()
        .take(8)
        .fold(0usize, |n, b| n.wrapping_mul(257).wrapping_add(*b as usize))
        % cases.len();
    let case = &cases[index];
    Some((
        case["input"].as_str()?.to_owned(),
        case["expected_stdout"].as_str()?.to_owned(),
        case["expected_exit"].as_i64()?,
    ))
}

pub fn check_fixture_oracles(data: &[u8]) {
    let (input, expected, exit) = format_fixture(data).unwrap();
    check_fixture(&input, &expected, exit);
    static CONTEXT: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    let context = CONTEXT.get_or_init(|| {
        serde_json::from_str(include_str!("../../tests/fixtures/context-workflows.json")).unwrap()
    });
    let cases = context["cases"].as_array().unwrap();
    let index = data
        .iter()
        .rev()
        .take(8)
        .fold(0usize, |n, b| n.wrapping_mul(257).wrapping_add(*b as usize))
        % cases.len();
    let case = &cases[index];
    check_fixture(
        case["stdin_utf8"].as_str().unwrap(),
        case["expect"]["stdout_utf8"].as_str().unwrap(),
        case["expect"]["exit_code"].as_i64().unwrap(),
    );
    // A checked-in seed also replays its own exact oracle, rather than relying
    // only on the arbitrary input's span consistency or sampled fixture index.
    static EXACT: std::sync::OnceLock<std::collections::HashMap<String, (String, i64)>> =
        std::sync::OnceLock::new();
    let exact = EXACT.get_or_init(|| {
        let formats: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/secret-formats.json")).unwrap();
        let mut map = std::collections::HashMap::new();
        for case in formats["cases"].as_array().unwrap() {
            insert_oracle(
                &mut map,
                case["input"].as_str().unwrap(),
                case["expected_stdout"].as_str().unwrap(),
                case["expected_exit"].as_i64().unwrap(),
            );
        }
        for case in cases {
            insert_oracle(
                &mut map,
                case["stdin_utf8"].as_str().unwrap(),
                case["expect"]["stdout_utf8"].as_str().unwrap(),
                case["expect"]["exit_code"].as_i64().unwrap(),
            );
        }
        map
    });
    if let Ok(input) = std::str::from_utf8(data)
        && let Some((expected, exit)) = exact.get(input)
    {
        check_fixture(input, expected, *exit);
    }
}

fn insert_oracle(
    map: &mut std::collections::HashMap<String, (String, i64)>,
    input: &str,
    expected: &str,
    exit: i64,
) {
    let next = (expected.to_owned(), exit);
    if let Some(previous) = map.insert(input.to_owned(), next.clone()) {
        assert_eq!(
            previous, next,
            "duplicate fixture input has conflicting independent oracles"
        );
    }
}

fn check_fixture(input: &str, expected: &str, exit: i64) {
    match redact::filter(input.as_bytes()) {
        Ok(output) => {
            assert_eq!(exit, 0);
            assert_eq!(output, expected);
        }
        Err(error) => {
            assert_eq!(exit, 2);
            assert!(expected.is_empty());
            let diagnostic = format!("{error} {error:?}");
            assert!(!diagnostic.contains("CREDENTIAL_CANARY_"));
            assert!(!diagnostic.contains("SYNTHETIC_FUZZ_CANARY_"));
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_literal_inventory_and_context_oracle_replays() {
        let formats: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/secret-formats.json"))
                .unwrap_or_else(|_| panic!("synthetic inventory setup failed"));
        for case in formats["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("synthetic cases missing"))
        {
            let input = case["input"]
                .as_str()
                .unwrap_or_else(|| panic!("synthetic input missing"));
            super::check_fixture_oracles(input.as_bytes());
        }
        let context: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/context-workflows.json"))
                .unwrap_or_else(|_| panic!("synthetic context setup failed"));
        for case in context["cases"]
            .as_array()
            .unwrap_or_else(|| panic!("synthetic cases missing"))
        {
            let input = case["stdin_utf8"]
                .as_str()
                .unwrap_or_else(|| panic!("synthetic input missing"));
            super::check_fixture_oracles(input.as_bytes());
        }
    }
}
