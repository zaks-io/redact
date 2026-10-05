#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65_536 {
        return;
    }
    if let Ok(input) = std::str::from_utf8(bytes) {
        match redact::detect(input) {
            Ok(spans) => {
                for span in spans {
                    assert!(
                        span.start < span.end
                            && span.end <= input.len()
                            && input.is_char_boundary(span.start)
                            && input.is_char_boundary(span.end)
                    );
                }
            }
            Err(error) => assert!(!format!("{error} {error:?}").contains("SYNTHETIC_FUZZ_CANARY_")),
        }
    }
    let suffix: String = bytes
        .iter()
        .take(256)
        .map(|b| char::from(b'A' + b % 26))
        .collect();
    let prefixes = [
        "ghp_",
        "github_pat_",
        "ghs_12345_",
        "ghr_",
        "glpat-",
        "glrt-",
        "npm_",
        "pypi-",
        "sk-proj-",
        "sk-ant-api03-",
        "sk_test_",
        "rk_live_",
        "whsec_",
        "xoxe.xoxb-",
        "xoxe.xapp-",
        "hvs.",
        "ops_",
        "vcp_",
        "lin_api_",
        "lin_oauth_",
        "ntn_",
        "secret_",
        "dop_v1_",
        "doo_v1_",
        "dor_v1_",
        "pul-",
        "glc_",
        "NRAK",
        "cfk_",
        "cfut_",
        "cfat_",
        "sb_secret_",
    ];
    let prefix = prefixes[bytes.first().copied().unwrap_or_default() as usize % prefixes.len()];
    let credential = format!("{prefix}SYNTHETIC_FUZZ_CANARY_{suffix}");
    let input = format!("status=failed [{credential}] retry=2\n");
    let expected = format!(
        "status=failed [[REDACTED sha256={}]] retry=2\n",
        redact_fuzz::hash(&credential)
    );
    assert_eq!(redact::filter(input.as_bytes()).unwrap(), expected);
    let mutated = format!("SYNTHETIC_FUZZ_CANARY_mutated_{suffix}");
    let field = [
        "GEMINI_API_KEY",
        "AccountKey",
        "privateKeyData",
        "_authToken",
        "AWS_SESSION_TOKEN",
        "client_secret",
        "refresh_token",
    ][bytes.last().copied().unwrap_or_default() as usize % 7];
    let input = format!("{{\"{field}\":\"{mutated}\",\"status\":\"failed\"}}");
    let expected = format!(
        "{{\"{field}\":\"[REDACTED sha256={}]\",\"status\":\"failed\"}}",
        redact_fuzz::hash(&mutated)
    );
    assert_eq!(redact::filter(input.as_bytes()).unwrap(), expected);
    redact_fuzz::check_fixture_oracles(bytes);
});
