# Codex App Transfer — Validation Report

> Scan date: 2026-05-29  
> Input: `finding_discovery_report.md` (12 candidates)  
> Method: static code trace + targeted logic analysis

---

## Validation Summary

| ID | Finding | Disposition | Confidence |
|---|---|---|---|
| FIND-001 | Unauthenticated Local Proxy | **VALID** | HIGH |
| FIND-002 | Plaintext Credential Storage | **VALID** | HIGH |
| FIND-003 | SSRF via Provider baseUrl | **VALID** | HIGH |
| FIND-004 | extraHeaders Disclosure | **VALID** | HIGH |
| FIND-005 | Feedback Redaction Bypass | **VALID** | HIGH |
| FIND-006 | CDP Port Race Condition | **VALID** | HIGH |
| FIND-007 | Linux Shell Injection Pattern | **VALID (pattern risk)** | MEDIUM |
| FIND-008 | MCP Arbitrary Command Execution | **VALID** | HIGH |
| FIND-009 | Tauri shell:allow-open | **VALID** | HIGH |
| FIND-010 | Path Traversal in AGENTS.md Paths | **VALID** | HIGH |
| FIND-011 | Update URL Restrictions | **MITIGATED** (signature check present) | MEDIUM |
| FIND-012 | Null CSP | **VALID** | HIGH |

---

## Detailed Validation

### FIND-001: Unauthenticated Local Proxy by Default

**Status:** VALID  
**Evidence:**
- `resolver.rs::StaticResolver::check_gateway()`:
  ```rust
  let Some(expected) = self.gateway_key.as_deref() else {
      return Ok(());   // <-- no auth required when gateway_key is None
  };
  ```
- `proxy_runner.rs::read_resolver_snapshot()` loads config and sets `gateway_key = cfg.gateway_api_key.filter(|s| !s.is_empty())`.
- Default registry (`registry_io.rs::load()`) sets `"gatewayApiKey": null`.
- `ProxyStatus` explicitly exposes `gateway_auth: false` when no key is configured.

**Conclusion:** Any process on the local machine can send requests to `127.0.0.1:18080` without authentication.

---

### FIND-002: Plaintext Credential Storage on Disk

**Status:** VALID  
**Evidence:**
- `registry_io.rs::load()` reads `~/.codex-app-transfer/config.json` via `load_raw_config()`, returning plaintext `serde_json::Value`.
- `registry_io.rs::save_raw_config()` writes the same plaintext JSON back.
- `public_provider()` redacts `apiKey` and `grokWeb` only for the frontend API response; the on-disk file retains everything in plaintext.
- OAuth tokens (`gemini_oauth.rs`, `antigravity_oauth.rs`) are persisted to `~/.codex-app-transfer/oauth_tokens.json` via `persist_token()`, with no encryption.

**Conclusion:** Credentials are stored in plaintext JSON files protected only by OS filesystem permissions.

---

### FIND-003: SSRF via User-Configurable Provider baseUrl

**Status:** VALID  
**Evidence:**
- `providers/crud.rs::add_provider()` accepts `baseUrl` from user input. The only validation is a grok.com-specific heuristic (`base_url_norm == "grok.com"`).
- `resolver.rs::resolve()` sets `upstream_base = provider.base_url.clone()` for non-OAuth providers.
- `forward.rs::build_upstream_url()` concatenates directly:
  ```rust
  fn build_upstream_url(upstream_base: &str, upstream_path: &str) -> String {
      let path = if upstream_path.starts_with('/') { ... } else { format!("/{}", upstream_path) };
      format!("{}{}", upstream_base.trim_end_matches('/'), path)
  }
  ```
- No blocklist for internal IPs (`169.254.169.254`, `127.0.0.1`, `10.0.0.0/8`, etc.), no scheme enforcement beyond what `reqwest` does.

**Conclusion:** An attacker who can modify provider config (UI or filesystem) can redirect proxy traffic to arbitrary internal/external URLs.

---

### FIND-004: extraHeaders Values Disclosed to Frontend

**Status:** VALID  
**Evidence:**
- `registry_io.rs::public_provider()`:
  ```rust
  out.remove("apiKey");
  out.remove("extraHeaders");   // <-- NOT removed
  out.insert("hasApiKey".into(), Value::Bool(has_key));
  out.remove("grokWeb");
  out.insert("hasGrokWeb".into(), Value::Bool(has_grok_web));
  ```
- `extraHeaders` is returned in full because `public_provider()` does not remove or redact it.
- Frontend calls `/api/providers` and receives the complete `extraHeaders` map, which may contain secondary credentials.

**Conclusion:** `extraHeaders` values are exposed to the frontend API, contradicting the redaction intent applied to `apiKey`/`grokWeb`.

---

### FIND-005: Feedback Diagnostic Bundle Redaction Bypass

**Status:** VALID  
**Evidence:**
- `feedback.rs::redacted_json()` uses substring matching:
  ```rust
  let is_sensitive_key = key_lower.contains("apikey")
      || key_lower.contains("api_key")
      || key_lower.contains("authorization")
      || key_lower.contains("token")
      || key_lower.contains("secret")
      || key_lower.contains("password");
  ```
- This misses field names like `privateKey`, `credentials`, `jwt`, `ssoToken`, `cfClearance`, `statsigId`, `cookie`, `session`.
- The recursive redaction only operates on keys; values in arrays or deeply nested objects may not be fully traversed if the parent key doesn't match.
- Error snapshots included in feedback bundles come from proxy telemetry logs, which are not subject to redaction before bundling.

**Conclusion:** Substring-based redaction is incomplete and will miss credentials stored under non-matching field names.

---

### FIND-006: CDP Debug Port Race Condition / Unauthenticated Access

**Status:** VALID  
**Evidence:**
- `process.rs::detect_free_cdp_port()` probes `127.0.0.1:9222` by attempting `TcpListener::bind`, then dropping the listener. This creates a TOCTOU race window.
- `codex_plugin_unlocker.rs` connects to `http://127.0.0.1:{port}/json/list` and then opens a WebSocket to the CDP target without any authentication handshake.
- CDP is a powerful debugging protocol; connecting to it grants full DOM access, JavaScript execution, local storage inspection, and network traffic interception within the target renderer.
- No TLS, no token, and no origin check on the CDP connection.

**Conclusion:** A malicious local process can bind to port 9222 before Codex Desktop starts (race) or connect to an already-running CDP port to execute arbitrary JavaScript in the Codex Desktop context.

---

### FIND-007: Linux Shell Injection Pattern

**Status:** VALID (pattern risk, not currently exploitable without code change)  
**Evidence:**
- `process.rs::open_command("linux", ...)` returns:
  ```rust
  vec![
      "sh".into(),
      "-c".into(),
      format!("{LINUX_BIN_NAME}{args_str} >/dev/null 2>&1 &"),
  ]
  ```
- `args_str` is built from `extra_args.join(" ")`.
- Currently, `extra_args` only comes from `should_attach_debug_port()`, which returns either `[]` or `["--remote-debugging-port=9222"]` — both hardcoded and safe.
- **However**, the `open_command` function signature accepts `&[String]` and uses `sh -c`. If any future caller passes user-influenced arguments, shell metacharacters would be interpreted.

**Conclusion:** The pattern is unsafe. While not exploitable today, it is a latent vulnerability that will activate if `extra_args` becomes attacker-controllable.

---

### FIND-008: MCP Server Configuration Allows Arbitrary Command Execution

**Status:** VALID  
**Evidence:**
- `mcp_servers.rs::McpServerSpec` defines:
  ```rust
  pub command: String,
  pub args: Vec<String>,
  pub env: HashMap<String, String>,
  pub cwd: Option<String>,
  ```
- `mcp.rs::upsert_server(Json(spec))` writes this directly to `~/.codex/config.toml` via `mcp_servers::upsert_server()`, which uses `toml_edit`.
- There is **no** validation of `command` against a blocklist, no path traversal check on `cwd`, and no restriction on `env` keys/values.
- Codex Desktop (the upstream OpenAI app) will later execute this command when loading MCP servers.

**Conclusion:** The app acts as a privileged conduit for arbitrary command execution. A compromised frontend or malicious marketplace plugin can install MCP servers that run arbitrary commands.

---

### FIND-009: Tauri shell:allow-open Permission

**Status:** VALID  
**Evidence:**
- `capabilities/default.json`:
  ```json
  {
    "permissions": [
      "core:default",
      "shell:allow-open",
      "dialog:allow-open",
      "deep-link:default"
    ]
  }
  ```
- `shell:allow-open` permits the frontend to invoke `open` on arbitrary URLs and file paths.
- Combined with FIND-012 (null CSP), a frontend XSS vulnerability can immediately escalate to opening attacker-controlled URLs or triggering vulnerable OS file handlers.

**Conclusion:** The permission is broader than necessary for an admin UI and expands the XSS blast radius.

---

### FIND-010: Path Traversal in Custom AGENTS.md / memories / skills Paths

**Status:** VALID  
**Evidence:**
- `agents_md_paths.rs::add_path()`:
  ```rust
  let path = PathBuf::from(raw_path);
  if !path.is_absolute() { return Err(...); }
  if !path.exists() { return Err(...); }
  // No check that path is within expected directories
  ```
- `resolve_path_by_hash()` returns the exact stored path.
- `agents_md.rs::apply()` writes `input.content` to `target` (the resolved path) via `fs::write()`.
- The same pattern applies to `memories_md.rs` and `skills_md.rs` (all use `resolve_path_by_hash` + direct file write).

**Conclusion:** An attacker with frontend access can add arbitrary absolute paths and read/write their contents through the managed-block endpoints.

---

### FIND-011: User-Configurable Update URL Without Restriction

**Status:** MITIGATED (signature verification present, but residual risk remains)  
**Evidence:**
- `update.rs` fetches `latest.json` from `settings.updateUrl` (user-configurable).
- `download_asset_impl()` computes SHA256 and verifies it against the `sha256` field in `latest.json`.
- `verify_signed_bytes()` validates the RSA-3072 PKCS#1-v1.5 signature over `latest.json` bytes using a build-time embedded public key.
- **Residual risks:**
  1. `updateUrl` can be HTTP (not HTTPS) if the user or an attacker modifies config, exposing the download to MITM.
  2. The `reqwest` client follows up to 10 redirects; a DNS hijacker could redirect to an attacker-controlled HTTPS site (signature would still fail, but the user sees a confusing error).
  3. Self-host users must fork and rebuild to change the public key; there is no certificate pinning or public-key rotation.

**Conclusion:** The signature check is a strong mitigation. Downgrade to HTTP or redirect attacks are possible but cannot produce a valid signature without the private key. Severity downgraded to P2.

---

### FIND-012: Null CSP in Tauri Configuration

**Status:** VALID  
**Evidence:**
- `tauri.conf.json`:
  ```json
  "security": {
    "csp": null
  }
  ```
- Tauri documentation recommends setting a strict CSP to prevent XSS from escalating to backend command execution.
- With `csp: null`, inline scripts, `eval()`, and remote script loading are unrestricted within the webview.
- Combined with `shell:allow-open` and `dialog:allow-open`, XSS can directly invoke privileged Tauri APIs.

**Conclusion:** The absence of CSP significantly increases the impact of any frontend XSS vulnerability.

---

## Rejected / Not Confirmed

None. All 12 candidates were validated or assessed as mitigated with residual risk.
