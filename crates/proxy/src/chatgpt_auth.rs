//! Shared ChatGPT auth classification helpers.

/// Extract the token from an `Authorization: Bearer ...` value.
pub(crate) fn extract_bearer_token(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let (scheme, token) = trimmed.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let token = token.trim();
        (!token.is_empty()).then_some(token)
    } else {
        None
    }
}

/// Transfer gateway keys are not real ChatGPT auth and must not disable MOC-126 mock.
pub(crate) fn is_gateway_bearer(token: &str) -> bool {
    token.trim_start().starts_with("cas_")
}

/// True only when the bearer looks like a ChatGPT access token and matches the active
/// local `auth.json` token. This is intentionally stricter than JWT-shape matching.
pub(crate) fn is_active_chatgpt_bearer(token: &str) -> bool {
    is_chatgpt_access_token(token) && token_matches_active_chatgpt(token)
}

/// 判断 Bearer 是否是 OpenAI ChatGPT 的 access_token —— JWT(三段)且 payload 含
/// `https://api.openai.com/auth.chatgpt_account_id`。
pub(crate) fn is_chatgpt_access_token(token: &str) -> bool {
    use base64::Engine;
    let mut it = token.split('.');
    let payload = match (it.next(), it.next(), it.next(), it.next()) {
        (Some(_h), Some(p), Some(sig), None) if !sig.is_empty() && !p.is_empty() => p,
        _ => return false,
    };
    let Ok(raw) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return false;
    };
    v.get("https://api.openai.com/auth")
        .and_then(|a| a.get("chatgpt_account_id"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.trim().is_empty())
}

/// [connector P1 review] relay 放行的安全锚:incoming token 必须**逐字 == 本地活动
/// `auth.json` 里 Codex 真在用的 `tokens.access_token`。
pub(crate) fn token_matches_active_chatgpt(token: &str) -> bool {
    let base = std::env::var_os("CODEX_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".codex")));
    let Some(path) = base.map(|b| b.join("auth.json")) else {
        return false;
    };
    let Ok(content) = std::fs::read_to_string(&path) else {
        return false;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) else {
        return false;
    };
    if v.get("auth_mode").and_then(serde_json::Value::as_str) != Some("chatgpt") {
        return false;
    }
    v.get("tokens")
        .and_then(|t| t.get("access_token"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|active| !active.is_empty() && active == token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chatgpt_jwt(account_id: &str) -> String {
        use base64::Engine;
        let payload = serde_json::json!({
            "https://api.openai.com/auth": {"chatgpt_account_id": account_id}
        });
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        format!("eyJhbGciOiJub25lIn0.{p}.sig")
    }

    #[test]
    fn extracts_bearer_token_case_insensitively() {
        assert_eq!(extract_bearer_token("Bearer abc"), Some("abc"));
        assert_eq!(extract_bearer_token("bearer   abc  "), Some("abc"));
        assert_eq!(extract_bearer_token("Basic abc"), None);
        assert_eq!(extract_bearer_token("abc"), None);
    }

    #[test]
    fn gateway_bearer_is_cas_prefix_only() {
        assert!(is_gateway_bearer("cas_test"));
        assert!(!is_gateway_bearer("sk-test"));
        assert!(!is_gateway_bearer(&chatgpt_jwt("acc_test")));
    }

    #[test]
    fn active_chatgpt_bearer_requires_local_auth_match() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let active = chatgpt_jwt("acc_test");
        let mut f = std::fs::File::create(dir.path().join("auth.json")).unwrap();
        write!(
            f,
            r#"{{"auth_mode":"chatgpt","tokens":{{"access_token":"{active}","refresh_token":"rt"}}}}"#
        )
        .unwrap();
        std::env::set_var("CODEX_HOME", dir.path());

        assert!(is_active_chatgpt_bearer(&active));
        assert!(!is_active_chatgpt_bearer(&chatgpt_jwt("acc_other")));
        assert!(!is_active_chatgpt_bearer("cas_test"));

        std::env::remove_var("CODEX_HOME");
    }
}
