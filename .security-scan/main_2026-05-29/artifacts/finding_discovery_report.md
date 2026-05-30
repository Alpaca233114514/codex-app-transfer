# Codex App Transfer — Finding Discovery Report

> Scan date: 2026-05-29  
> Target: repository-wide (`main` branch)  
> Method: manual source-code review guided by threat model  
> Total candidate findings: 12

---

## FIND-001: Unauthenticated Local Proxy by Default

**Surface:** `crates/proxy/src/resolver.rs`, `src-tauri/src/proxy_runner.rs`  
**Class:** Information Disclosure / Elevation of Privilege  
**CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-319 (Cleartext Transmission of Sensitive Information)  
**Plausibility:** HIGH

**Evidence:**
- The proxy binds to `127.0.0.1` with a default port of `18080`.
- `gatewayApiKey` is optional (`None` by default). When absent, the proxy accepts any loopback request without authentication (`resolver.rs`: `gateway_key.is_some()` → `gateway_auth = false`).
- `ProxyStatus` exposes this as "无鉴权调试模式" (no-auth debug mode).
- Any local process (including browser JavaScript, other users' processes on shared hosts, or compromised applications) can send requests to the proxy, consuming API quota and potentially reading streamed responses.

**Impact:** Local attackers or co-tenant processes can exfiltrate API keys indirectly by sending requests through the proxy and observing responses, or exhaust upstream rate limits.

---

## FIND-002: Plaintext Credential Storage on Disk

**Surface:** `src-tauri/src/admin/registry_io.rs`, `~/.codex-app-transfer/config.json`  
**Class:** Information Disclosure  
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)  
**Plausibility:** HIGH

**Evidence:**
- `config.json` stores `apiKey`, `gatewayApiKey`, `grokWeb.cookies` (JWT/sso tokens), and OAuth tokens in plaintext JSON.
- No keychain, OS credential store, or encryption-at-rest is used.
- `registry_io.rs::load()` returns the raw JSON directly; `save()` writes directly to the user's config dir with standard file permissions (umask-dependent).
- Backup files created during import/export (`settings.rs`) retain full plaintext credentials.

**Impact:** Malware running as the same user, backups uploaded to cloud storage, or stolen laptops expose all API keys and session tokens.

---

## FIND-003: SSRF via User-Configurable Provider baseUrl

**Surface:** `crates/proxy/src/forward.rs`, `crates/proxy/src/resolver.rs`, `src-tauri/src/admin/handlers/providers/crud.rs`  
**Class:** Server-Side Request Forgery  
**CWE:** CWE-918 (Server-Side Request Forgery)  
**Plausibility:** HIGH

**Evidence:**
- `add_provider` / `update_provider` accept `baseUrl` from user input with no scheme restriction, no IP filtering, and no blocklist.
- The only `baseUrl` validation is a grok.com-specific heuristic (`base_url_norm == "grok.com"`).
- `build_upstream_url()` in `forward.rs` concatenates `upstream_base` (from provider config) with `upstream_path` via simple string formatting: `format!("{}{}", upstream_base.trim_end_matches('/'), path)`.
- `reqwest` then sends the request to this fully attacker-controlled URL.
- On cloud VMs or shared hosts, this could reach `http://169.254.169.254/` (AWS/Azure/GCP metadata), `http://localhost:<admin-port>/`, or internal services.

**Impact:** Attackers with UI access (or ability to write `config.json`) can force the proxy to send authenticated requests to internal endpoints, potentially exfiltrating cloud metadata or attacking other loopback services.

---

## FIND-004: extraHeaders Values Disclosed to Frontend

**Surface:** `src-tauri/src/admin/registry_io.rs::public_provider()`  
**Class:** Information Disclosure  
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**Plausibility:** HIGH

**Evidence:**
- `public_provider()` explicitly removes `apiKey` and `grokWeb`, replacing them with boolean flags (`hasApiKey`, `hasGrokWeb`).
- However, `extraHeaders` — which may contain secondary credentials (e.g., `X-Api-Key`, session cookies, custom auth tokens) — is returned in full to the frontend.
- Frontend code can read these values via the `/api/providers` endpoint.

**Impact:** A compromised frontend (XSS) or malicious browser extension can read `extraHeaders` credentials that were intended to be backend-only.

---

## FIND-005: Feedback Diagnostic Bundle Redaction Bypass

**Surface:** `src-tauri/src/admin/handlers/feedback.rs`  
**Class:** Information Disclosure  
**CWE:** CWE-200, CWE-532 (Insertion of Sensitive Information into Log File)  
**Plausibility:** MEDIUM

**Evidence:**
- `redacted_json()` recursively walks JSON and replaces values when keys contain substrings: `apikey`, `api_key`, `authorization`, `token`, `secret`, `password`.
- This substring-based approach misses novel or obfuscated field names (e.g., `privateKey`, `credentials`, `jwt`, `sso_rw`, `cf_clearance`).
- `sanitize_codex_toml()` uses a similar substring blocklist on TOML lines.
- The diagnostic bundle also includes "recent error snapshots" from proxy logs, which may contain upstream response bodies or request traces that were never designed for redaction.
- `codex-config.redacted.toml` and `proxy-config.redacted.json` are uploaded to `codex-app-transfer-feedback.mochance.xyz`.

**Impact:** Sensitive credentials may leak in feedback bundles if field names don't match the hardcoded blocklist, or if error snapshots contain unredacted upstream traffic.

---

## FIND-006: CDP Debug Port Race Condition / Unauthenticated Access

**Surface:** `src-tauri/src/codex_plugin_unlocker.rs`, `src-tauri/src/codex_theme_injector.rs`, `src-tauri/src/admin/services/desktop/process.rs`  
**Class:** Information Disclosure / Elevation of Privilege  
**CWE:** CWE-306, CWE-362 (Race Condition)  
**Plausibility:** MEDIUM

**Evidence:**
- On non-macOS platforms, the app probes for a free CDP port starting at `9222` (`detect_free_cdp_port`). If `9222` is occupied, it falls back to a random port.
- There is no authentication on the CDP WebSocket connection.
- A malicious local process can bind to `127.0.0.1:9222` before Codex Desktop starts. The app will then connect to the attacker's fake CDP endpoint and inject JavaScript (`setAuthMethod('chatgpt')`, CSS tokens, background images).
- Conversely, a malicious process can connect to the legitimate CDP port and execute arbitrary JavaScript in Codex Desktop's renderer context, exfiltrating OpenAI session data, local storage, and cookies.

**Impact:** Full compromise of the Codex Desktop renderer session; ability to read/modify the user's OpenAI web state.

---

## FIND-007: Linux Command Injection via Shell String Construction

**Surface:** `src-tauri/src/admin/services/desktop/process.rs::open_command()`  
**Class:** Command Injection  
**CWE:** CWE-78 (OS Command Injection)  
**Plausibility:** LOW-MEDIUM (currently controlled input, but fragile pattern)

**Evidence:**
- On Linux, `open_command` returns:
  ```rust
  vec![
      "sh".into(),
      "-c".into(),
      format!("{LINUX_BIN_NAME}{args_str} >/dev/null 2>&1 &"),
  ]
  ```
- `args_str` is built from `extra_args.join(" ")`.
- While `extra_args` currently only originates from `should_attach_debug_port()` (which returns hardcoded `--remote-debugging-port=9222` or `[]`), this is an unsafe pattern.
- If future code paths pass user-influenced arguments (e.g., custom CLI flags from settings), shell metacharacters would be interpreted by `sh`.

**Impact:** Potential arbitrary command execution if `extra_args` ever becomes attacker-influenced.

---

## FIND-008: MCP Server Configuration Allows Arbitrary Command Execution

**Surface:** `src-tauri/src/admin/services/mcp_servers.rs`, `src-tauri/src/admin/handlers/mcp.rs`  
**Class:** Elevation of Privilege / Arbitrary Code Execution  
**CWE:** CWE-78  
**Plausibility:** HIGH

**Evidence:**
- MCP server spec (`McpServerSpec`) allows `command`, `args[]`, `env{}`, and `cwd` for `Stdio` transport.
- `upsert_server()` in `mcp.rs` accepts a JSON `McpServerSpec` directly and writes it to `~/.codex/config.toml` via `toml_edit`.
- There is no validation of `command` (e.g., rejecting `sh`, `bash`, `cmd.exe`, `powershell.exe`), no path restrictions, and no argument sanitization.
- Codex Desktop will later execute this command when loading MCP servers.
- The app effectively acts as a privileged launcher for arbitrary subprocesses configured through its UI.

**Impact:** Any user (or compromised frontend) can configure MCP servers that execute arbitrary commands with the user's privileges when Codex Desktop loads them.

---

## FIND-009: Tauri shell:allow-open Permission Expands Attack Surface

**Surface:** `src-tauri/capabilities/default.json`  
**Class:** Elevation of Privilege  
**CWE:** CWE-269 (Improper Privilege Management)  
**Plausibility:** MEDIUM

**Evidence:**
- `capabilities/default.json` grants `shell:allow-open` to the `main` window.
- This permission allows the frontend to open arbitrary URLs and file paths using the OS default handler.
- Combined with any frontend XSS vulnerability (see FIND-012), this could be used to open malicious URLs, trigger other installed applications, or exploit OS handler vulnerabilities.

**Impact:** Frontend XSS can escalate to arbitrary URL/file opening, potentially chaining with other application vulnerabilities.

---

## FIND-010: Path Traversal in Custom AGENTS.md / memories / skills Paths

**Surface:** `src-tauri/src/admin/services/agents_md_paths.rs::add_path()`, `src-tauri/src/admin/handlers/agents_md.rs`, `src-tauri/src/admin/handlers/memories_md.rs`  
**Class:** Path Traversal / Arbitrary File Read-Write  
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)  
**Plausibility:** MEDIUM

**Evidence:**
- `add_path(raw_path)` checks `is_absolute()` and `exists()`, but does not restrict the path to be within the user's project directories or home folder.
- An attacker with frontend access (or ability to write `codex-doc-paths.json`) can add paths like `/etc/passwd`, `C:\Users\<target>\ sensitivedata.txt`, or `/home/otheruser/.ssh/id_rsa`.
- Once added, endpoints like `GET /api/codex/agents-md/raw?hash=...` will read and return the file content.
- The `apply`, `rollback`, and `write` endpoints can write to arbitrary absolute paths.

**Impact:** Arbitrary file read/write on the local filesystem, limited only by the OS user's permissions.

---

## FIND-011: User-Configurable Update URL Without Restriction

**Surface:** `src-tauri/src/admin/handlers/update.rs`, `src-tauri/src/admin/handlers/settings.rs`  
**Class:** Supply-Chain / Code Execution  
**CWE:** CWE-494 (Download of Code Without Integrity Check), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)  
**Plausibility:** LOW-MEDIUM

**Evidence:**
- `settings.updateUrl` is user-configurable and defaults to `https://api.github.com/...`.
- The app fetches `latest.json` from this URL, then downloads and installs the referenced asset.
- `latest.json` and the asset binary are verified with RSA-3072 + SHA256 (`verify_signed_bytes`).
- However, the URL itself can be downgraded from HTTPS to HTTP via DNS hijacking or captive portals, and the `reqwest` client follows redirects (up to 10).
- Self-host users must fork and rebuild to change the embedded public key; there is no runtime public-key rotation or pinning.

**Impact:** A network attacker who can manipulate DNS or serve a malicious `latest.json` over HTTP could trick users into downloading malware, although signature verification would fail unless the attacker also possesses the private key.

---

## FIND-012: Null CSP in Tauri Configuration

**Surface:** `src-tauri/tauri.conf.json`  
**Class:** Cross-Site Scripting (XSS) enabler  
**CWE:** CWE-693 (Protection Mechanism Failure), CWE-79 (Cross-site Scripting)  
**Plausibility:** MEDIUM

**Evidence:**
- `tauri.conf.json` sets `"csp": null`, disabling Content-Security-Policy entirely.
- The frontend is served via `cas://localhost/` with `withGlobalTauri: true`, giving the frontend full access to the `__TAURI__` IPC bridge.
- Without CSP, any XSS vulnerability in the frontend (e.g., via a malicious provider name, model name, or error message rendered unsafely) can execute with the full privileges of the Tauri webview.

**Impact:** A frontend XSS vulnerability could escalate to arbitrary backend command execution (via `shell:allow-open`) and filesystem access (via `dialog:allow-open`).

---

## Summary by Priority

| ID | Finding | Priority | Validation Recommended |
|---|---|---|---|
| FIND-001 | Unauthenticated Local Proxy | P0 | Yes |
| FIND-002 | Plaintext Credential Storage | P0 | Yes |
| FIND-003 | SSRF via Provider baseUrl | P0 | Yes |
| FIND-004 | extraHeaders Disclosure | P1 | Yes |
| FIND-005 | Feedback Redaction Bypass | P1 | Yes |
| FIND-006 | CDP Port Race Condition | P1 | Yes |
| FIND-007 | Linux Shell Injection Pattern | P1 | Yes |
| FIND-008 | MCP Arbitrary Command Execution | P0 | Yes |
| FIND-009 | Tauri shell:allow-open | P1 | Yes |
| FIND-010 | Path Traversal in AGENTS.md Paths | P1 | Yes |
| FIND-011 | Update URL Restrictions | P2 | Yes |
| FIND-012 | Null CSP | P1 | Yes |
