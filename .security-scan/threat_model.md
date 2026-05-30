# Codex App Transfer — Repository Threat Model

> Scope: entire repository (`codex-app-transfer`)  
> Generated: 2026-05-29  
> Product: Tauri-based desktop companion for OpenAI Codex Desktop. Provides local HTTP proxy for multi-provider LLM routing, CDP-based UI injection, OAuth management, and desktop process orchestration.

---

## 1. Product Surfaces & Trust Boundaries

### 1.1 Core Surfaces

| Surface | Technology | Exposure | Privilege |
|---|---|---|---|
| **Embedded Admin UI** | Tauri webview (`cas://localhost/`) | Local only (custom URI scheme) | Same user |
| **Local HTTP Proxy** | axum on `127.0.0.1` (default 18080) | Loopback only | Same user |
| **Codex Desktop CDP** | WebSocket to `127.0.0.1:9222` (or ephemeral) | Loopback only | Same user |
| **Feedback Worker** | HTTPS to `codex-app-transfer-feedback.mochance.xyz` | Internet | Same user |
| **Update Check** | HTTPS to configurable `updateUrl` | Internet | Same user |
| **OAuth Flows** | HTTPS to Google / Antigravity endpoints | Internet | Same user |
| **External LLM APIs** | HTTPS via proxy to provider endpoints | Internet | Same user |
| **MCP Server Management** | Local stdio/HTTP/WebSocket processes | Local | Same user |

### 1.2 Trust Boundaries

1. **TB-1: Webview ↔ Backend**  
   The frontend runs in a Tauri webview with `withGlobalTauri: true`. Commands are dispatched via `cas://localhost/` to an in-process axum router. No TCP socket is exposed, but the webview has access to the `__TAURI__` bridge.

2. **TB-2: Proxy ↔ External Providers**  
   The proxy strips and rewrites `Authorization` headers, injects provider-specific auth (`Bearer`, `X-Api-Key`), and forwards request bodies. Provider responses are streamed back byte-for-byte.

3. **TB-3: Backend ↔ Codex Desktop**  
   The app reads/writes `~/.codex/{config.toml,auth.json}` and spawns/kills the Codex Desktop process. It also connects to Codex Desktop's CDP debug port to inject JavaScript for theming and plugin unlocking.

4. **TB-4: User Data ↔ Filesystem**  
   Config, snapshots, logs, and OAuth tokens are stored under `~/.codex-app-transfer/` and `~/.codex/`. File permissions depend on the host OS umask.

5. **TB-5: OAuth Token Storage**  
   OAuth tokens (Gemini, Antigravity) are persisted to `~/.codex-app-transfer/oauth_tokens.json` or similar. These are long-lived credentials with cloud-provider scope.

---

## 2. Attacker-Controlled Inputs

### 2.1 Direct Inputs
- **Provider configuration JSON** (`config.json`): `apiKey`, `extraHeaders`, `baseUrl`, `modelMappings`, `grokWeb.cookies`, etc.
- **HTTP proxy request body**: `model` field, arbitrary JSON payload forwarded to upstream.
- **Feedback form**: `message`, `email`, `contactType`, `diagnosticData` (including env info, config snapshots, recent errors).
- **Settings JSON**: `theme`, `language`, `proxyPort`, `adminPort`, `updateUrl`, `codexUiTheme`.
- **MCP server configuration**: command paths, arguments, environment variables.
- **OAuth redirect parameters**: `code`, `state` (Google/Antigravity flows).
- **Update response JSON**: version, URL, checksums.
- **CDP WebSocket messages**: responses from Codex Desktop's DevTools protocol.
- **Codex Desktop file contents**: `~/.codex/config.toml`, `auth.json` (read/written by snapshot/restore).

### 2.2 Indirect / Supply-Chain Inputs
- **Frontend static assets**: `frontend/` directory compiled into binary via `include_dir!`. Compromise of build-time assets affects all users.
- **OAuth discovery documents**: `.well-known/openid-configuration` (fetched at runtime).
- **Provider API responses**: streamed through proxy to Codex Desktop.
- **MCP marketplace plugin manifests**: JSON fetched from marketplace sources.
- **Theme assets**: `src-tauri/resources/themes/*` compiled into binary via `include_bytes!`.

---

## 3. Security-Relevant Assets

| Asset | Location | Sensitivity |
|---|---|---|
| API keys (OpenAI, DeepSeek, Kimi, etc.) | `~/.codex-app-transfer/config.json` | **Critical** |
| OAuth tokens (Gemini, Antigravity) | `~/.codex-app-transfer/oauth_tokens.json` | **Critical** |
| Gateway API key (proxy auth) | `~/.codex-app-transfer/config.json` | **High** |
| Grok web cookies / statsigId | `~/.codex-app-transfer/config.json` | **High** |
| Codex Desktop auth/session | `~/.codex/auth.json` | **Critical** |
| User snapshots / backups | `~/.codex-app-transfer/snapshots/` | **High** |
| Feedback diagnostic bundles | `~/.codex-app-transfer/feedback_bundles/` | **Medium** |
| Proxy session cache | `~/.codex-app-transfer/sessions.db` | **Medium** |
| MCP server env/args | `~/.codex/config.toml` | **High** |

---

## 4. Assumptions

1. The host OS user account is trusted; this app does not protect against malware already running as the same user.
2. The local loopback interface (`127.0.0.1`) is not accessible to other users on the same machine (holds for single-user desktops, may fail on shared servers).
3. Codex Desktop's CDP port is bound to loopback and not exposed externally.
4. The frontend assets bundled at compile time are benign (build-time integrity is out of scope for runtime scans).
5. TLS certificate validation for external HTTPS calls is performed by `reqwest` with default settings (system CA store).
6. OAuth `state` parameter validation prevents CSRF during login flows.
7. The Tauri `csp: null` means no additional Content-Security-Policy is enforced by Tauri; the frontend is responsible for its own XSS hygiene.

---

## 5. Threat Scenarios by STRIDE

### Spoofing (S)
- **S1**: Malicious local process binds to the proxy port (18080) before the app starts, intercepting LLM requests and API keys.
- **S2**: A fake Codex Desktop process exposes a CDP endpoint on 9222; the app connects and injects scripts into an attacker-controlled browser.
- **S3**: OAuth `state` parameter is predictable or reused, allowing an attacker to complete login as a different user.

### Tampering (T)
- **T1**: Attacker modifies `config.json` on disk to redirect proxy traffic to an attacker-controlled `baseUrl` (provider hijacking).
- **T2**: Attacker modifies `~/.codex/config.toml` or `auth.json` via snapshot pollution or incomplete restore, leading to Codex Desktop misconfiguration.
- **T3**: Malicious provider `extraHeaders` injects additional HTTP headers into upstream requests (e.g., header smuggling).
- **T4**: Update mechanism fetches from attacker-controlled `updateUrl` and executes unverified code.

### Repudiation (R)
- **R1**: Proxy logs and session cache may not retain sufficient forensic detail to reconstruct which provider/model was used for a given request.
- **R2**: Feedback submission is throttled but not strongly authenticated; an attacker with local access could spam the feedback endpoint.

### Information Disclosure (I)
- **I1**: API keys and OAuth tokens are stored in plaintext JSON on disk; no encryption at rest.
- **I2**: Feedback diagnostic bundles may include sensitive config values if redaction logic is incomplete.
- **I3**: Proxy runs without gateway auth by default (`gatewayApiKey` is optional); any local process can send requests through the proxy.
- **I4**: CDP connection to Codex Desktop exposes the full DOM and JavaScript execution context; a malicious local process connecting to the same CDP port can exfiltrate data.
- **I5**: `config.json` backups are created on import/export; old backups may retain revoked credentials.
- **I6**: Registry `public_provider()` redacts `apiKey` and `grokWeb`, but `extraHeaders` values are returned in full to the frontend (high sensitivity if headers contain credentials).

### Denial of Service (D)
- **D1**: Malicious local process floods the proxy with requests, exhausting rate limits or upstream quota.
- **D2**: Malicious provider `baseUrl` returns infinite SSE stream, exhausting local memory.
- **D3**: CDP script injection causes Codex Desktop renderer crash or infinite loop.
- **D4**: Excessive snapshot creation fills the user's disk.

### Elevation of Privilege (E)
- **E1**: Tauri `shell:allow-open` permission allows the frontend to open arbitrary URLs/files via the OS default handler.
- **E2**: `dialog:allow-open` allows the frontend to open file dialogs; combined with other bugs could lead to arbitrary file read.
- **E3**: Desktop process spawning uses dynamic command construction (`sh -c` on Linux); malicious `CODEX_DESKTOP_PATH` or similar environment variables could inject commands.
- **E4**: MCP server configuration allows arbitrary command execution with user privileges; a malicious MCP plugin manifest could specify a harmful command.
- **E5**: The app has `deep-link:default` permission; a malicious deep link (`codex-app-transfer://...`) could trigger unintended actions if the app handles deep-link payloads without validation.

---

## 6. Vulnerability Classes (Repository Context)

### A. Command Injection / Unsafe Process Spawning
Relevant: `desktop/process.rs`, `admin/handlers/desktop.rs`, `admin/handlers/mcp.rs`  
Risk: Dynamic construction of shell commands or process arguments from user-controlled paths/config.

### B. Path Traversal / Arbitrary File Read-Write
Relevant: `admin/registry_io.rs`, `admin/handlers/settings.rs`, `admin/handlers/skills_md.rs`, `admin/handlers/agents_md.rs`, `admin/handlers/memories_md.rs`  
Risk: User-controlled filenames or paths used in filesystem operations without sanitization.

### C. SSRF / Open Redirect via Proxy
Relevant: `crates/proxy/src/forward.rs`, `crates/proxy/src/resolver.rs`  
Risk: The proxy forwards requests to `baseUrl`; a malicious config could redirect traffic to internal services (e.g., `http://169.254.169.254/` on cloud VMs).

### D. Credential Storage / Information Disclosure
Relevant: `admin/registry_io.rs`, `admin/handlers/providers/crud.rs`, `admin/handlers/feedback.rs`  
Risk: Plaintext credential storage, incomplete redaction in API responses, sensitive data in feedback bundles.

### E. CDP Injection / XSS-like Code Execution
Relevant: `codex_plugin_unlocker.rs`, `codex_theme_injector.rs`  
Risk: JavaScript injected into Codex Desktop runs with the full privileges of the Codex Desktop renderer (including access to local storage, cookies, and the OpenAI web session).

### F. Header Injection / HTTP Request Smuggling
Relevant: `crates/proxy/src/resolver.rs`, `admin/handlers/providers/crud.rs`  
Risk: `extraHeaders` values containing newlines or control characters could split HTTP requests or inject headers.

### G. Insecure Deserialization / Config Parsing
Relevant: `admin/registry_io.rs`, `admin/handlers/settings.rs`  
Risk: `serde_json` from untrusted import data or malicious `config.json` could cause panics or logic errors.

### H. OAuth State/CSRF Issues
Relevant: `admin/handlers/gemini_oauth.rs`, `admin/handlers/antigravity_oauth.rs`, `crates/gemini_oauth/src/lib.rs`  
Risk: Missing or weak `state` validation, predictable PKCE verifiers, or token storage without binding to the initiating session.

### I. Supply-Chain / Update Integrity
Relevant: `admin/handlers/update.rs`  
Risk: Downloaded update binaries or signatures are not verified, or the update URL is user-configurable without restriction.

### J. CORS / CSP Bypass
Relevant: `tauri.conf.json` (`csp: null`), `admin/static_files.rs`  
Risk: No CSP enforced by Tauri; frontend XSS could escalate to backend command execution via `__TAURI__` bridge.

---

## 7. Risk Priorities

| Priority | Threat | Rationale |
|---|---|---|
| **P0** | I1 (plaintext credentials) | API keys and OAuth tokens are high-value assets stored without encryption. |
| **P0** | I3 (unauthenticated proxy) | Default-open proxy allows any local process to consume quota and exfiltrate data. |
| **P0** | E3/E4 (command injection) | Process spawning and MCP configuration are direct code execution paths. |
| **P1** | T1 (provider hijacking) | Attacker with filesystem access can redirect all LLM traffic and capture keys. |
| **P1** | C (SSRF) | Proxy could reach internal cloud metadata endpoints on shared/multi-user hosts. |
| **P1** | I4 (CDP data exposure) | CDP is a powerful debugging interface; shared-localhost exposure is dangerous. |
| **P1** | E1/E2 (Tauri permission abuse) | `shell:allow-open` + `dialog:allow-open` expand the frontend attack surface. |
| **P2** | I2 (feedback leakage) | Diagnostic bundles may leak secrets if redaction misses new fields. |
| **P2** | T4 (unverified updates) | Custom `updateUrl` could be used for phishing or malware delivery. |
| **P2** | H (OAuth weaknesses) | Weak state/CSRF protection could allow account takeover. |
| **P2** | J (CSP bypass) | Frontend XSS is less severe without additional backend exposure, but still relevant. |

---

## 8. Scan Guidance

### Focus Areas for Finding Discovery
1. **All filesystem paths** constructed from user input in `admin/handlers/*_md.rs`, `settings.rs`, `desktop.rs`.
2. **All `Command::new` / `std::process::Command` invocations** in `desktop/process.rs`, `mcp.rs`, and any crate using `tokio::process`.
3. **Proxy forwarding logic** in `crates/proxy/src/forward.rs` and `resolver.rs`, especially URL construction, header injection, and body parsing.
4. **CDP WebSocket message handling** in `codex_plugin_unlocker.rs` and `codex_theme_injector.rs` — untrusted JSON from CDP responses.
5. **OAuth token storage and state generation** in `gemini_oauth.rs`, `antigravity_oauth.rs`, and `crates/gemini_oauth/src/lib.rs`.
6. **Registry redaction logic** in `registry_io.rs` — ensure no sensitive fields leak through `public_provider()`.
7. **Feedback bundle assembly** in `feedback.rs` — verify all sensitive fields are redacted before upload.
8. **Update download and verification** in `update.rs` — signature checks, hash verification, path restrictions.
9. **Tauri capability file** `capabilities/default.json` — assess if permissions are minimal.
10. **MCP server/plugin installation** — command validation, path restrictions, manifest validation.

### Out-of-Scope / Deferred
- Build-time supply chain (npm, crates.io dependencies) — not reviewed in this source-only scan.
- Frontend JavaScript security (XSS within the admin UI) — partially covered via CSP/Tauri permissions, but deep frontend review is deferred.
- macOS entitlements / Windows code signing / MSIX packaging details.
- Physical access attacks (cold-boot memory extraction, disk forensics).
