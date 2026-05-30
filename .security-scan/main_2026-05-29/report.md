# Codex App Transfer — Security Scan Report

> **Repository:** `Cmochance/codex-app-transfer`  
> **Branch:** `main`  
> **Scan Date:** 2026-05-29  
> **Scanner:** Codex Security Plugin (full-repository scan)  
> **Scope:** Entire repository — Tauri backend, embedded proxy, CDP injectors, OAuth handlers, MCP management, and configuration surfaces  
> **Methodology:** STRIDE threat modeling → manual source-code finding discovery → static validation → attack-path analysis

---

## Executive Summary

This security scan identified **11 valid security findings** and **1 mitigated finding with residual risk** across the Codex App Transfer codebase. The application acts as a privileged companion to OpenAI's Codex Desktop, managing AI provider credentials, local HTTP proxying, Chrome DevTools Protocol (CDP) injection, and MCP server orchestration. Several findings involve high-impact attack paths including arbitrary command execution, credential exposure, and server-side request forgery (SSRF).

| Severity | Count | Findings |
|---|---|---|
| **CRITICAL** | 1 | MCP Arbitrary Command Execution (AP-003) |
| **HIGH** | 5 | Unauthenticated Proxy + SSRF (AP-001), Credential Harvesting (AP-002), CDP Session Hijacking (AP-004), Path Traversal (AP-005) |
| **MEDIUM-HIGH** | 1 | XSS → Tauri Escalation (AP-006) |
| **MEDIUM** | 2 | Feedback Bundle Leakage (AP-007), Linux Shell Injection Pattern (AP-008) |
| **LOW-MEDIUM** | 1 | Update Mechanism Residual Risk (AP-009, suppressed) |
| **MITIGATED** | 1 | Update Signature Verification (FIND-011) |

**Top Recommendations (by impact/effort):**
1. **Enforce proxy gateway authentication by default** or bind to a Unix domain socket / named pipe.
2. **Encrypt credentials at rest** using the OS keychain (Keychain on macOS, DPAPI/Credential Manager on Windows, Secret Service on Linux).
3. **Validate and sandbox MCP server commands** — restrict to an allowlist or use a sandboxed execution environment.
4. **Add SSRF protection** to provider `baseUrl` — block internal IPs, localhost, and metadata endpoints.
5. **Redact `extraHeaders` in `public_provider()`** before returning to the frontend.
6. **Refactor Linux `open_command`** to avoid `sh -c` string interpolation.
7. **Add a strict Content-Security-Policy** in `tauri.conf.json`.
8. **Use a blocklist + regex-based approach** for feedback diagnostic redaction instead of substring matching.

---

## 1. Threat Model Summary

Codex App Transfer is a Tauri-based desktop application with the following security-relevant surfaces:

- **Embedded Admin UI** served via Tauri custom URI scheme (`cas://localhost/`) with in-process axum routing.
- **Local HTTP Proxy** on `127.0.0.1:18080` (default) that intercepts and forwards LLM API requests to configured providers.
- **CDP Injection** into Codex Desktop via WebSocket to `127.0.0.1:9222` for theming and plugin unlocking.
- **OAuth Flows** for Gemini and Antigravity Google Cloud Code Assist.
- **MCP Server/Plugin Management** that writes server configurations to `~/.codex/config.toml`.
- **Feedback Submission** to a Cloudflare Worker endpoint with diagnostic bundle attachments.

### Key Trust Boundaries
1. Webview frontend ↔ Tauri backend (`cas://localhost/`)
2. Proxy ↔ External LLM providers (user-configurable `baseUrl`)
3. Backend ↔ Codex Desktop process (CDP, file snapshots, process spawning)
4. User data ↔ Local filesystem (`~/.codex-app-transfer/`, `~/.codex/`)
5. OAuth token storage (`~/.codex-app-transfer/oauth_tokens.json`)

---

## 2. Findings

### CRITICAL

#### [C-001] MCP Server Configuration Allows Arbitrary Command Execution

- **Attack Path:** AP-003
- **CWE:** CWE-78 (OS Command Injection)
- **Files:** `src-tauri/src/admin/services/mcp_servers.rs`, `src-tauri/src/admin/handlers/mcp.rs`
- **Description:** The MCP server upsert endpoint accepts arbitrary `command`, `args`, `env`, and `cwd` values with no validation or sandboxing. Codex Desktop later executes these commands when loading MCP servers, leading to arbitrary code execution with the user's OS privileges.
- **Impact:** Full remote code execution (RCE) on the user's machine.
- **Exploitation:** Single `POST /api/codex/mcp/servers` request from a compromised frontend or malicious marketplace plugin.
- **Remediation:**
  - Validate `command` against an allowlist (e.g., `node`, `python`, `npx`).
  - Reject shell interpreters (`sh`, `bash`, `cmd.exe`, `powershell.exe`).
  - Sand MCP server execution using seccomp, containers, or a restricted subprocess environment.
  - Restrict `cwd` to a user-data subdirectory.

---

### HIGH

#### [H-001] Local Proxy Unauthenticated by Default + SSRF

- **Attack Path:** AP-001
- **CWE:** CWE-306 (Missing Authentication), CWE-918 (SSRF)
- **Files:** `crates/proxy/src/resolver.rs`, `crates/proxy/src/forward.rs`, `src-tauri/src/admin/handlers/providers/crud.rs`
- **Description:** The proxy binds to `127.0.0.1:18080` without requiring a gateway API key by default. Any local process can send requests through it. Furthermore, provider `baseUrl` is user-configurable with no SSRF filtering, allowing the proxy to send authenticated requests to internal services (cloud metadata, localhost admin API, etc.).
- **Impact:** Cloud metadata exfiltration, internal service attack, quota theft.
- **Exploitation:** Send HTTP request to `127.0.0.1:18080` with a provider whose `baseUrl` points to an internal endpoint.
- **Remediation:**
  - Generate a random gateway key on first launch and require it for all proxy requests.
  - Or bind the proxy to a Unix domain socket / Windows named pipe instead of TCP.
  - Add SSRF filtering: block `169.254.169.254`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and non-HTTP(S) schemes.

#### [H-002] Credentials Stored in Plaintext + extraHeaders Leaked to Frontend

- **Attack Path:** AP-002
- **CWE:** CWE-312 (Cleartext Storage), CWE-200 (Information Disclosure)
- **Files:** `src-tauri/src/admin/registry_io.rs`, `src-tauri/src/admin/handlers/providers/crud.rs`
- **Description:** API keys, OAuth tokens, and grokWeb cookies are stored in plaintext JSON (`~/.codex-app-transfer/config.json`). Additionally, `public_provider()` redacts `apiKey` and `grokWeb` but leaves `extraHeaders` fully exposed in the frontend API response.
- **Impact:** Credential theft via filesystem access, backups, or frontend XSS.
- **Remediation:**
  - Store credentials in the OS keychain / credential store instead of plaintext JSON.
  - Redact `extraHeaders` values in `public_provider()` (or replace with boolean flags like `hasExtraHeaders`).
  - Encrypt backup files created during import/export.

#### [H-003] CDP Debug Port Race Condition / Unauthenticated Access

- **Attack Path:** AP-004
- **CWE:** CWE-306, CWE-362 (Race Condition)
- **Files:** `src-tauri/src/codex_plugin_unlocker.rs`, `src-tauri/src/codex_theme_injector.rs`, `src-tauri/src/admin/services/desktop/process.rs`
- **Description:** The app connects to Codex Desktop's CDP port (9222 by default) without authentication. A malicious local process can bind to this port before Codex Desktop starts (race condition) or connect to the already-running port to execute arbitrary JavaScript in the renderer context.
- **Impact:** Full compromise of the user's OpenAI Codex Desktop session.
- **Remediation:**
  - Do not expose CDP on a fixed port; use port 0 and communicate the port via a secure channel.
  - On macOS, the `DevToolsActivePort` file approach is better but still readable by any local process. Consider using a private pipe.
  - If CDP is required, restrict it to a token-authenticated endpoint.

#### [H-004] Path Traversal in Custom Document Paths

- **Attack Path:** AP-005
- **CWE:** CWE-22 (Path Traversal)
- **Files:** `src-tauri/src/admin/services/agents_md_paths.rs`, `src-tauri/src/admin/handlers/agents_md.rs`, `src-tauri/src/admin/handlers/memories_md.rs`, `src-tauri/src/admin/handlers/skills_md.rs`
- **Description:** Custom path endpoints for AGENTS.md, memories, and skills accept arbitrary absolute paths. The only checks are `is_absolute()` and `exists()`. An attacker can read/write any file the OS user has access to.
- **Impact:** Arbitrary file read/write.
- **Remediation:**
  - Restrict custom paths to be within the user's home directory or project directories.
  - Validate paths using `canonicalize()` and ensure they remain within an allowed base directory.
  - Reject paths containing `..` segments after normalization.

#### [H-005] Tarball Plugin Installation — Path Traversal Risk

- **Attack Path:** (Related to AP-003)
- **CWE:** CWE-22 (Path Traversal via tar archive)
- **Files:** `src-tauri/src/admin/services/codex_plugins.rs`
- **Description:** Plugin tarball extraction uses `tar::Archive::unpack()`. While the `tar` crate rejects absolute paths and `..` by default, symlink-based path traversal within the archive may still be possible depending on the crate version and platform.
- **Impact:** Arbitrary file write during plugin installation.
- **Remediation:**
  - After unpacking, recursively resolve all symlinks and verify final paths are within the staged directory.
  - Consider using a sandboxed extraction library or chroot.

---

### MEDIUM-HIGH

#### [MH-001] Null CSP + Tauri shell:allow-open Expands XSS Blast Radius

- **Attack Path:** AP-006
- **CWE:** CWE-693, CWE-79 (XSS)
- **Files:** `src-tauri/tauri.conf.json`, `src-tauri/capabilities/default.json`
- **Description:** Tauri is configured with `"csp": null`, disabling Content-Security-Policy. Combined with `shell:allow-open`, any XSS vulnerability in the frontend can escalate to opening arbitrary URLs and files via the OS.
- **Impact:** Phishing, chain exploitation with OS handler vulnerabilities.
- **Remediation:**
  - Add a strict CSP in `tauri.conf.json` (e.g., `default-src 'self'; script-src 'self';`).
  - Review whether `shell:allow-open` and `dialog:allow-open` are strictly necessary; remove if not.
  - Sanitize all user-controlled strings rendered in the frontend.

---

### MEDIUM

#### [M-001] Feedback Diagnostic Bundle Redaction Bypass

- **Attack Path:** AP-007
- **CWE:** CWE-200, CWE-532
- **Files:** `src-tauri/src/admin/handlers/feedback.rs`
- **Description:** Feedback diagnostic bundles use substring-based redaction (`apikey`, `token`, `secret`, `password`, etc.). This misses novel field names (e.g., `privateKey`, `jwt`, `credentials`, `cf_clearance`) and does not redact proxy telemetry error snapshots.
- **Impact:** Credentials may leak to the feedback worker operator.
- **Remediation:**
  - Use a regex-based or structured-schema approach to redact all leaf values under known credential keys.
  - Extend the blocklist to include `privateKey`, `jwt`, `credentials`, `cookie`, `session`, `certificate`.
  - Redact or exclude proxy telemetry logs from feedback bundles.

#### [M-002] Linux Command Injection Pattern (Latent)

- **Attack Path:** AP-008
- **CWE:** CWE-78
- **Files:** `src-tauri/src/admin/services/desktop/process.rs`
- **Description:** On Linux, `open_command()` uses `sh -c "codex{args_str} >/dev/null 2>&1 &"` where `args_str` is built by joining `extra_args`. While `extra_args` is currently hardcoded, this pattern is unsafe and will become exploitable if user-controlled arguments are ever passed.
- **Impact:** Arbitrary command execution (latent).
- **Remediation:**
  - Refactor to `Command::new(LINUX_BIN_NAME).args(extra_args).spawn()` without shell interpolation.

---

### LOW-MEDIUM (Suppressed)

#### [LM-001] Update URL Configurable with Residual Network Risk

- **Attack Path:** AP-009
- **CWE:** CWE-494, CWE-829
- **Files:** `src-tauri/src/admin/handlers/update.rs`
- **Description:** The `updateUrl` is user-configurable. However, `latest.json` and downloaded assets are cryptographically verified with RSA-3072 + SHA256 using a build-time embedded public key. A network attacker cannot forge a valid signature without the private key.
- **Residual Risk:** HTTP downgrade could leak update metadata; redirect chains could confuse users.
- **Remediation:**
  - Enforce HTTPS for `updateUrl`.
  - Add certificate or public-key pinning.

---

## 3. Attack Path Summary

| ID | Path | Attacker | Entry Point | Impact | Severity |
|---|---|---|---|---|---|
| AP-001 | Local proxy → SSRF → internal metadata | Local process / co-tenant | `127.0.0.1:18080` | Cloud metadata exfiltration | HIGH |
| AP-002 | Plaintext config + frontend API → credential theft | Malware / XSS / stolen laptop | Filesystem or `/api/providers` | Account takeover, quota theft | HIGH |
| AP-003 | MCP server injection → arbitrary command execution | Compromised frontend / malicious plugin | `POST /api/codex/mcp/servers` | RCE | CRITICAL |
| AP-004 | CDP port hijacking → OpenAI session compromise | Local process | `127.0.0.1:9222` | Session hijacking | HIGH |
| AP-005 | Path traversal → arbitrary file read/write | Compromised frontend | `POST /api/codex/agents-md/paths/add` | File system compromise | HIGH |
| AP-006 | XSS → Tauri `shell:allow-open` escalation | Malicious provider response | Frontend rendering | Phishing, OS handler abuse | MEDIUM-HIGH |
| AP-007 | Feedback bundle → incomplete redaction → credential leak | Feedback worker operator | User feedback submission | Credential leakage | MEDIUM |
| AP-008 | (Latent) `sh -c` injection if extra_args becomes user-controlled | Future attacker | Settings UI / config | RCE | MEDIUM |
| AP-009 | Update URL hijacking → signature verification blocks it | Network MITM | DNS / network path | Update blocked (mitigated) | LOW-MEDIUM |

---

## 4. Coverage & Scope

### In-Scope Surfaces Reviewed
- [x] Tauri command handlers (`admin/handlers/*.rs`)
- [x] Embedded HTTP proxy (`crates/proxy/src/`)
- [x] CDP plugin unlocker and theme injector
- [x] OAuth flow handlers (Gemini, Antigravity)
- [x] Registry I/O and credential redaction
- [x] MCP server/plugin management
- [x] Desktop process spawning and snapshot management
- [x] Feedback submission and diagnostic bundling
- [x] Update mechanism and signature verification
- [x] Tauri capabilities and CSP configuration

### Out-of-Scope / Deferred
- [ ] Frontend JavaScript XSS deep-dive (partially covered via CSP/Tauri permissions)
- [ ] Build-time supply chain (npm, crates.io dependencies)
- [ ] macOS entitlements / Windows code signing / MSIX packaging
- [ ] Physical access attacks
- [ ] Network-level penetration testing of external endpoints

---

## 5. Remediation Priority Roadmap

### Immediate (P0 — days)
1. **AP-003 (C-001):** Add MCP command allowlist/blocklist validation. Reject shell interpreters.
2. **AP-001 (H-001):** Require gateway auth by default or switch proxy to Unix socket / named pipe.
3. **AP-002 (H-002):** Redact `extraHeaders` in `public_provider()` before returning to frontend.

### Short-term (P1 — 1-2 weeks)
4. **AP-002 (H-002):** Migrate credential storage from plaintext JSON to OS keychain.
5. **AP-001 (H-001):** Add SSRF filtering for provider `baseUrl`.
6. **AP-005 (H-004):** Add path traversal guards to custom document path endpoints.
7. **AP-004 (H-003):** Remove fixed CDP port; use ephemeral port with secure parent-child communication.
8. **AP-006 (MH-001):** Add strict CSP and review Tauri capability grants.

### Medium-term (P2 — 2-4 weeks)
9. **AP-007 (M-001):** Improve feedback redaction with regex + extended blocklist.
10. **AP-008 (M-002):** Refactor Linux `open_command` to avoid `sh -c`.
11. **AP-009 (LM-001):** Enforce HTTPS for update URL and add pinning.
12. **H-005:** Harden tarball extraction against symlink traversal.

---

## 6. Appendix

### A. Scan Artifacts

| Artifact | Path |
|---|---|
| Threat Model | `.security-scan/threat_model.md` |
| Finding Discovery Report | `.security-scan/main_2026-05-29/artifacts/finding_discovery_report.md` |
| Validation Report | `.security-scan/main_2026-05-29/artifacts/validation_report.md` |
| Attack-Path Analysis Report | `.security-scan/main_2026-05-29/artifacts/attack_path_analysis_report.md` |
| Final Report (this file) | `.security-scan/main_2026-05-29/report.md` |

### B. Tools & Methods
- Static source-code analysis (manual review)
- STRIDE threat modeling
- Source-to-sink tracing
- Rust standard library and Tauri security model review

### C. Glossary
| Term | Definition |
|---|---|
| CDP | Chrome DevTools Protocol |
| CSP | Content-Security-Policy |
| MCP | Model Context Protocol (Codex plugin system) |
| SSRF | Server-Side Request Forgery |
| Tauri | Rust-based desktop application framework |
| TOCTOU | Time-of-check to time-of-use (race condition) |
