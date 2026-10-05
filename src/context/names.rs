/// Context identifies sensitivity, never credential validity or provider identity.
pub(crate) fn sensitive_name(name: &str) -> bool {
    let mut normalized = String::new();
    let mut characters = name.chars().peekable();
    let mut previous = None;
    while let Some(character) = characters.next() {
        if matches!(character, '-' | '.' | ' ' | '\t') {
            normalized.push('_');
        } else {
            if character.is_ascii_uppercase()
                && previous.is_some_and(|prior: char| {
                    prior.is_ascii_lowercase()
                        || prior.is_ascii_digit()
                        || prior.is_ascii_uppercase()
                            && characters.peek().is_some_and(char::is_ascii_lowercase)
                })
            {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
        }
        previous = Some(character);
    }
    let plain = name
        .to_ascii_lowercase()
        .replace(['-', '.', ' ', '\t'], "_");
    let suffixes = [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "secret_key",
        "private_key",
        "client_secret",
        "credential",
        "credentials",
        "authorization",
        "pat",
        "license_key",
        "service_role_key",
    ];
    suffixes.iter().any(|suffix| {
        [&normalized, &plain].iter().any(|name| {
            name.strip_suffix(suffix)
                .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('_'))
        })
    }) || [&normalized, &plain].iter().any(|name| {
        matches!(
            name.as_str(),
            "accountkey"
                | "account_key"
                | "sharedaccesssignature"
                | "shared_access_signature"
                | "privatekeydata"
                | "private_key_data"
                | "_authtoken"
                | "authtoken"
                | "clientsecret"
                | "accesstoken"
                | "refreshtoken"
                | "sessiontoken"
                | "secretaccesskey"
                | "awssecretaccesskey"
                | "awssessiontoken"
                | "privatekey"
                | "passwordhash"
                | "password_hash"
                | "sslpassword"
                | "dd_api_key"
                | "dd_application_key"
                | "x_shopify_access_token"
                | "_gitlab_session"
                | "cookie"
                | "set_cookie"
                | "tokenvalue"
                | "token_value"
                | "_auth"
        )
    })
}
