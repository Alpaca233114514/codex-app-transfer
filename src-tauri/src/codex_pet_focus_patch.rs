//! Codex Desktop pet/avatar overlay anti-focus workaround (MOC-36).
//!
//! Codex Desktop exposes the avatar overlay as a separate CDP page whose URL
//! contains `avatar-overlay`. This module injects a small renderer-side patch
//! into that page only, leaving the main Codex Desktop page untouched.

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};

use crate::codex_plugin_unlocker::{current_cdp_url, CDP_PORT};

pub const SETTING_SUPPRESS_PET_FOCUS_STEAL: &str = "suppressCodexPetFocusSteal";

/// Missing setting defaults to enabled because the workaround is the bug fix.
pub fn suppress_pet_focus_steal_enabled(settings: &Value) -> bool {
    settings
        .get(SETTING_SUPPRESS_PET_FOCUS_STEAL)
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

pub fn suppress_pet_focus_steal_enabled_from_registry() -> bool {
    crate::admin::registry_io::load()
        .ok()
        .and_then(|cfg| cfg.get("settings").cloned())
        .map(|settings| suppress_pet_focus_steal_enabled(&settings))
        .unwrap_or(true)
}

/// Best-effort one-shot injection. Callers should log failures but not block
/// Codex startup or settings save on them.
pub async fn apply_if_enabled() -> Result<usize, String> {
    if !suppress_pet_focus_steal_enabled_from_registry() {
        tracing::info!("[PetFocusPatch] disabled by settings");
        return Ok(0);
    }
    apply_patch().await
}

async fn apply_patch() -> Result<usize, String> {
    let targets = locate_avatar_overlay_ws_urls().await?;
    if targets.is_empty() {
        tracing::warn!("[PetFocusPatch] no avatar-overlay CDP target found");
        return Ok(0);
    }

    let mut applied = 0usize;
    for ws_url in targets {
        match inject_into_target(&ws_url).await {
            Ok(()) => {
                applied += 1;
                tracing::info!(ws_url = %ws_url, "[PetFocusPatch] injected into avatar overlay");
            }
            Err(e) => {
                tracing::warn!(
                    ws_url = %ws_url,
                    error = %e,
                    "[PetFocusPatch] inject failed for avatar overlay"
                );
            }
        }
    }
    Ok(applied)
}

async fn locate_avatar_overlay_ws_urls() -> Result<Vec<String>, String> {
    if CDP_PORT.load(std::sync::atomic::Ordering::Relaxed) == 0 {
        return Err("CDP port not ready".to_owned());
    }
    let resp = reqwest::get(current_cdp_url())
        .await
        .map_err(|e| format!("CDP /json/list request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("CDP /json/list returned {}", resp.status()));
    }
    let pages: Vec<Value> = resp
        .json()
        .await
        .map_err(|e| format!("CDP /json/list JSON parse failed: {e}"))?;
    Ok(avatar_overlay_ws_urls(&pages))
}

fn avatar_overlay_ws_urls(pages: &[Value]) -> Vec<String> {
    pages
        .iter()
        .filter_map(|p| {
            let url = p.get("url").and_then(Value::as_str).unwrap_or("");
            let ptype = p.get("type").and_then(Value::as_str).unwrap_or("");
            if ptype == "page" && url.contains("avatar-overlay") {
                p.get("webSocketDebuggerUrl")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            } else {
                None
            }
        })
        .collect()
}

async fn inject_into_target(ws_url: &str) -> Result<(), String> {
    let (ws_stream, _) = connect_async(ws_url)
        .await
        .map_err(|e| format!("CDP websocket connect failed: {e}"))?;
    let (mut write, mut read) = ws_stream.split();

    let (msg, _) = make_msg(1, "Page.enable", json!({}));
    write
        .send(WsMessage::Text(msg))
        .await
        .map_err(|e| format!("CDP Page.enable send failed: {e}"))?;
    drain_until_response(&mut read, 1).await?;

    let script = anti_focus_script();
    let (msg, _) = make_msg(
        2,
        "Page.addScriptToEvaluateOnNewDocument",
        json!({ "source": script }),
    );
    write
        .send(WsMessage::Text(msg))
        .await
        .map_err(|e| format!("CDP addScript send failed: {e}"))?;
    drain_until_response(&mut read, 2).await?;

    let (msg, _) = make_msg(
        3,
        "Runtime.evaluate",
        json!({ "expression": script, "returnByValue": true }),
    );
    write
        .send(WsMessage::Text(msg))
        .await
        .map_err(|e| format!("CDP Runtime.evaluate send failed: {e}"))?;
    drain_until_response(&mut read, 3).await?;

    let _ = write.close().await;
    Ok(())
}

fn make_msg(id: u64, method: &str, params: Value) -> (String, u64) {
    (json!({ "id": id, "method": method, "params": params }).to_string(), id)
}

async fn drain_until_response(
    read: &mut (impl StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>> + Unpin),
    expected_id: u64,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        if tokio::time::Instant::now() > deadline {
            return Err(format!("CDP response timeout for id={expected_id}"));
        }
        match tokio::time::timeout(Duration::from_millis(500), read.next()).await {
            Ok(Some(Ok(WsMessage::Text(t)))) => {
                let val: Value = match serde_json::from_str(&t) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if val.get("id").is_none() || val["id"].as_u64() != Some(expected_id) {
                    continue;
                }
                if let Some(err) = val.get("error") {
                    return Err(format!("CDP error for id={expected_id}: {err}"));
                }
                if let Some(exception) = val.get("result").and_then(|r| r.get("exceptionDetails")) {
                    return Err(format!(
                        "CDP exception for id={expected_id}: {exception}"
                    ));
                }
                return Ok(());
            }
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => return Err(format!("CDP read error: {e}")),
            Ok(None) => return Err("CDP connection closed".to_owned()),
            Err(_) => continue,
        }
    }
}

fn anti_focus_script() -> &'static str {
    ANTI_FOCUS_SCRIPT
}

const ANTI_FOCUS_SCRIPT: &str = r#"
(function() {
  if (window.__codexAppTransferPetFocusPatchV1) return "already-patched";
  Object.defineProperty(window, "__codexAppTransferPetFocusPatchV1", {
    value: true,
    configurable: false,
    enumerable: false,
    writable: false
  });

  var BLOCK_RE = /focus|activate|show.*window|window.*show|raise|front/i;
  var ALLOW_RE = /devtools|log|telemetry|metrics|resize|position|bounds|move|drag|mouse|pointer/i;
  function shouldBlock(channel) {
    var text = String(channel || "");
    return BLOCK_RE.test(text) && !ALLOW_RE.test(text);
  }
  function blockResult(channel) {
    try { console.debug("[codex-app-transfer] blocked pet focus IPC:", String(channel)); } catch (_) {}
    return undefined;
  }

  try { window.focus = function() {}; } catch (_) {}
  try { window.blur = function() {}; } catch (_) {}

  function patchIpc(ipc) {
    if (!ipc || ipc.__codexAppTransferPetFocusPatchV1) return;
    try {
      ["send", "sendSync", "invoke"].forEach(function(name) {
        var original = ipc[name];
        if (typeof original !== "function") return;
        ipc[name] = function(channel) {
          if (shouldBlock(channel)) return blockResult(channel);
          return original.apply(this, arguments);
        };
      });
      Object.defineProperty(ipc, "__codexAppTransferPetFocusPatchV1", {
        value: true,
        configurable: false
      });
    } catch (_) {}
  }

  try {
    if (typeof require === "function") {
      var electron = require("electron");
      patchIpc(electron && electron.ipcRenderer);
    }
  } catch (_) {}

  ["electron", "api", "codex", "desktop", "bridge"].forEach(function(key) {
    try {
      var bridge = window[key];
      if (!bridge || bridge.__codexAppTransferPetFocusPatchV1) return;
      ["send", "sendSync", "invoke", "postMessage", "emit"].forEach(function(name) {
        var original = bridge[name];
        if (typeof original !== "function") return;
        bridge[name] = function(channel) {
          if (shouldBlock(channel)) return blockResult(key + "." + channel);
          return original.apply(this, arguments);
        };
      });
      Object.defineProperty(bridge, "__codexAppTransferPetFocusPatchV1", {
        value: true,
        configurable: false
      });
    } catch (_) {}
  });

  return "patched";
})();
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setting_defaults_to_enabled() {
        assert!(suppress_pet_focus_steal_enabled(&json!({})));
        let enabled = json!({ SETTING_SUPPRESS_PET_FOCUS_STEAL.to_owned(): true });
        assert!(suppress_pet_focus_steal_enabled(&enabled));
        let disabled = json!({ SETTING_SUPPRESS_PET_FOCUS_STEAL.to_owned(): false });
        assert!(!suppress_pet_focus_steal_enabled(&disabled));
    }

    #[test]
    fn avatar_overlay_filter_only_returns_overlay_pages() {
        let pages = json!([
            {"type":"page","url":"file:///index.html","webSocketDebuggerUrl":"ws://main"},
            {"type":"page","url":"file:///index.html#avatar-overlay","webSocketDebuggerUrl":"ws://overlay"},
            {"type":"iframe","url":"avatar-overlay","webSocketDebuggerUrl":"ws://iframe"},
            {"type":"page","url":"avatar-overlay"}
        ]);
        let urls = avatar_overlay_ws_urls(pages.as_array().unwrap());
        assert_eq!(urls, vec!["ws://overlay"]);
    }

    #[test]
    fn script_contains_focus_and_ipc_patches() {
        let script = anti_focus_script();
        assert!(script.contains("__codexAppTransferPetFocusPatchV1"));
        assert!(script.contains("window.focus"));
        assert!(script.contains("ipcRenderer"));
        assert!(script.contains("focus|activate"));
    }
}
