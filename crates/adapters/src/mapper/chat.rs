use bytes::Bytes;
use codex_app_transfer_registry::Provider;
use futures_util::stream::{self, Stream, StreamExt};
use http::{header::HeaderValue, HeaderMap, StatusCode};
use serde_json::{json, Value};
use std::pin::Pin;

use crate::core::routes;
use crate::mapper::{RequestMapper, ResponseMapper};
use crate::responses::{
    compact, convert_chat_to_responses_stream_with_options, global_response_session_cache,
    responses_body_to_chat_body_for_provider_with_session,
};
use crate::types::{AdapterError, ByteStream, RequestPlan, ResponsePlan};
use crate::codex_error_code_for_upstream_status;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ChatResponsesMapper;

const MAX_UPSTREAM_ERROR_BODY_BYTES: usize = 64 * 1024;
const MAX_USER_ERROR_MESSAGE_CHARS: usize = 2_000;

/// 哪些 provider 需要 `<think>...</think>` 兜底拆分。
/// 目前只有 MiniMax 的 OpenAI-compatible 端点在不开启 `reasoning_split` 时
/// 会把思考过程塞进 content 的 `<think>` 标签里,需要兜底解析。
pub(crate) fn provider_needs_think_tag_split(provider: &Provider) -> bool {
    let needles = [&provider.id, &provider.name, &provider.base_url];
    needles.iter().any(|value| {
        let lower = value.to_ascii_lowercase();
        lower.contains("minimax") || lower.contains("minimaxi")
    })
}

/// responses adapter 请求侧编排：
/// - `/responses/compact` 走 compact 本地包装
/// - 其他 `/responses*` 走 responses->chat 主管道转换
pub(crate) fn prepare_responses_request(
    client_path: &str,
    body: Bytes,
    provider: &Provider,
) -> Result<RequestPlan, AdapterError> {
    if compact::is_compact_path(client_path) {
        let new_body = compact::build_compact_chat_request(&body, provider)?;
        return Ok(RequestPlan {
            upstream_path: "/chat/completions".to_owned(),
            body: Bytes::from(new_body),
            upstream_headers: http::HeaderMap::new(),
            response_session: None,
            adapter_metadata: None,
            is_compact: true,
            original_responses_request: None,
        });
    }

    let upstream_path = routes::redirect_responses_to_chat(client_path);
    let parsed: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| AdapterError::BadRequest(format!("body 不是合法 JSON: {e}")))?;
    let original_responses_request = Some(parsed.clone());
    let conversion = responses_body_to_chat_body_for_provider_with_session(
        &parsed,
        Some(provider),
        Some(global_response_session_cache()),
    )?;
    let new_body = serde_json::to_vec(&conversion.body)
        .map_err(|e| AdapterError::Internal(format!("re-serialize: {e}")))?;
    // fix(#210 P1-1): 传递 history_lost 标志到 adapter_metadata,
    // transform_response_stream 据此注入 X-Session-History-Lost header
    let adapter_metadata = if conversion.history_lost {
        Some(serde_json::json!({"history_lost": true}))
    } else {
        None
    };
    Ok(RequestPlan {
        upstream_path,
        body: Bytes::from(new_body),
        upstream_headers: http::HeaderMap::new(),
        response_session: Some(conversion.response_session),
        adapter_metadata,
        is_compact: false,
        original_responses_request,
    })
}

/// responses adapter 响应侧编排：
/// - compact 走 compact response 包装
/// - 其余路径走 chat SSE -> responses SSE 转换
pub(crate) fn transform_responses_response_stream(
    upstream_status: StatusCode,
    mut upstream_headers: HeaderMap,
    upstream_stream: ByteStream,
    provider: &Provider,
    request_plan: &RequestPlan,
) -> Result<ResponsePlan, AdapterError> {
    if request_plan.is_compact {
        return compact::build_compact_response_plan(
            upstream_status,
            upstream_headers,
            upstream_stream,
        );
    }
    upstream_headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    upstream_headers.remove(http::header::CONTENT_LENGTH);
    upstream_headers.remove(http::header::CONTENT_ENCODING);
    // fix(#210 P1-1): cache miss 降级时注入信号 header,让客户端感知历史丢失
    if request_plan
        .adapter_metadata
        .as_ref()
        .and_then(|m| m.get("history_lost"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        upstream_headers.insert(
            http::HeaderName::from_static("x-session-history-lost"),
            HeaderValue::from_static("1"),
        );
    }
    if !upstream_status.is_success() {
        return Ok(ResponsePlan {
            status: StatusCode::OK,
            headers: upstream_headers,
            stream: convert_chat_error_to_responses_failure_stream(
                upstream_status,
                upstream_stream,
                request_plan.original_responses_request.clone(),
            ),
        });
    }
    let enable_think_tag_split = provider_needs_think_tag_split(provider);
    Ok(ResponsePlan {
        status: upstream_status,
        headers: upstream_headers,
        stream: convert_chat_to_responses_stream_with_options(
            upstream_stream,
            request_plan.response_session.clone(),
            enable_think_tag_split,
            request_plan.original_responses_request.clone(),
        ),
    })
}

fn convert_chat_error_to_responses_failure_stream(
    upstream_status: StatusCode,
    upstream_stream: ByteStream,
    original_request: Option<Value>,
) -> ByteStream {
    let status_u16 = upstream_status.as_u16();
    let s: Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>> = Box::pin(
        stream::unfold(
            (upstream_stream, original_request, false),
            move |(mut input, orig, finished)| async move {
                if finished {
                    return None;
                }

                let mut body = Vec::with_capacity(1024);
                let mut transport_err: Option<String> = None;
                let mut truncated = false;
                while let Some(chunk) = input.next().await {
                    match chunk {
                        Ok(b) => {
                            let remaining =
                                MAX_UPSTREAM_ERROR_BODY_BYTES.saturating_sub(body.len());
                            if remaining == 0 {
                                truncated = true;
                                break;
                            }
                            let take = b.len().min(remaining);
                            body.extend_from_slice(&b[..take]);
                            if take < b.len() {
                                truncated = true;
                                break;
                            }
                        }
                        Err(e) => {
                            transport_err = Some(e.to_string());
                            break;
                        }
                    }
                }

                let was_lossy = std::str::from_utf8(&body).is_err();
                let raw_text = String::from_utf8_lossy(&body).into_owned();
                let parsed: Option<Value> = serde_json::from_str(&raw_text).ok();
                let (upstream_message, upstream_status_text, upstream_error_kind) =
                    extract_upstream_error_fields(parsed.as_ref(), &raw_text, status_u16);

                let mut code = codex_error_code_for_upstream_status(
                    status_u16,
                    upstream_status_text.as_deref(),
                    upstream_message.as_deref(),
                )
                .to_owned();
                let mut error_message = build_error_message(
                    status_u16,
                    upstream_message.as_deref(),
                    transport_err.as_deref(),
                    truncated,
                    was_lossy,
                );
                let mut final_kind = upstream_error_kind;
                if transport_err.is_some() {
                    final_kind = "transport_error".to_owned();
                }
                if error_message.chars().count() > MAX_USER_ERROR_MESSAGE_CHARS {
                    let truncated_msg: String = error_message
                        .chars()
                        .take(MAX_USER_ERROR_MESSAGE_CHARS)
                        .collect();
                    error_message = format!("{truncated_msg}…");
                }

                let out = build_response_failed_sse(
                    orig,
                    &code,
                    &error_message,
                    status_u16,
                    &final_kind,
                );
                Some((Ok(Bytes::from(out)), (input, None, true)))
            },
        ),
    );
    s
}

fn extract_upstream_error_fields(
    parsed: Option<&Value>,
    raw_text: &str,
    status_u16: u16,
) -> (Option<String>, Option<String>, String) {
    let extract_message = |v: &Value| -> Option<String> {
        v.get("error")
            .and_then(|e| {
                e.get("message")
                    .or_else(|| e.get("error"))
                    .or_else(|| e.get("detail"))
            })
            .and_then(|m| m.as_str())
            .map(String::from)
            .or_else(|| {
                v.get("message")
                    .or_else(|| v.get("detail"))
                    .and_then(|m| m.as_str())
                    .map(String::from)
            })
    };
    let extract_status = |v: &Value| -> Option<String> {
        v.get("error")
            .and_then(|e| e.get("status").or_else(|| e.get("type")).or_else(|| e.get("code")))
            .and_then(|s| {
                s.as_str()
                    .map(String::from)
                    .or_else(|| s.as_i64().map(|n| n.to_string()))
            })
            .or_else(|| {
                v.get("status")
                    .or_else(|| v.get("type"))
                    .or_else(|| v.get("code"))
                    .and_then(|s| {
                        s.as_str()
                            .map(String::from)
                            .or_else(|| s.as_i64().map(|n| n.to_string()))
                    })
            })
    };

    let upstream_message = match parsed {
        Some(v) if v.is_object() => extract_message(v),
        Some(v) => match v.as_array().and_then(|a| a.first()) {
            Some(first) => extract_message(first),
            None => None,
        },
        None => {
            let trimmed = raw_text.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
    };
    let upstream_status_text = match parsed {
        Some(v) if v.is_object() => extract_status(v),
        Some(v) => match v.as_array().and_then(|a| a.first()) {
            Some(first) => extract_status(first),
            None => None,
        },
        None => None,
    };
    let upstream_error_kind = infer_upstream_error_kind(
        status_u16,
        upstream_status_text.as_deref(),
        upstream_message.as_deref(),
    );
    (upstream_message, upstream_status_text, upstream_error_kind)
}

fn infer_upstream_error_kind(
    status_u16: u16,
    upstream_status_text: Option<&str>,
    upstream_message: Option<&str>,
) -> String {
    let status_lower = upstream_status_text
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let message_lower = upstream_message
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    match status_u16 {
        400 => "bad_request".to_owned(),
        401 => "auth_error".to_owned(),
        403 => "permission_denied".to_owned(),
        404 => "not_found".to_owned(),
        405 => "method_not_allowed".to_owned(),
        408 | 504 => "timeout".to_owned(),
        429 => {
            if status_lower == "resource_exhausted"
                || message_lower.contains("quota")
                || message_lower.contains("resource_exhausted")
            {
                "quota_exceeded".to_owned()
            } else {
                "rate_limited".to_owned()
            }
        }
        500..=599 => "server_error".to_owned(),
        _ => "upstream_error".to_owned(),
    }
}

fn build_error_message(
    status_u16: u16,
    upstream_message: Option<&str>,
    transport_err: Option<&str>,
    truncated: bool,
    was_lossy: bool,
) -> String {
    let mut msg = match upstream_message {
        Some(m) => format!("Upstream error (HTTP {status_u16}): {m}"),
        None => format!("Upstream error (HTTP {status_u16})"),
    };
    if let Some(te) = transport_err {
        msg.push_str(&format!(" [transport error: {te}]"));
    }
    if truncated {
        msg.push_str(" [body truncated]");
    }
    if was_lossy {
        msg.push_str(" [non-UTF-8 body]");
    }
    msg
}

fn build_response_failed_sse(
    original_request: Option<Value>,
    code: &str,
    message: &str,
    http_status: u16,
    upstream_error_kind: &str,
) -> Vec<u8> {
    let response_id = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("resp_{nanos:x}")
    };
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let model = original_request
        .as_ref()
        .and_then(|r| r.get("model"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let req_field_or = |key: &str, fallback: Value| -> Value {
        original_request
            .as_ref()
            .and_then(|v| v.get(key))
            .cloned()
            .unwrap_or(fallback)
    };
    let mut sequence_number = 0_u64;
    let mut envelope = json!({
        "id": response_id,
        "object": "response",
        "created_at": created_at,
        "status": "failed",
        "model": model,
        "tools": req_field_or("tools", json!([])),
        "tool_choice": req_field_or("tool_choice", json!("auto")),
        "parallel_tool_calls": req_field_or("parallel_tool_calls", json!(true)),
        "reasoning": req_field_or("reasoning", json!({"effort": null, "summary": null})),
        "text": req_field_or("text", json!({"format": {"type": "text"}})),
        "metadata": req_field_or("metadata", Value::Null),
        "previous_response_id": req_field_or("previous_response_id", Value::Null),
        "instructions": req_field_or("instructions", Value::Null),
        "temperature": req_field_or("temperature", Value::Null),
        "top_p": req_field_or("top_p", Value::Null),
        "max_output_tokens": req_field_or("max_output_tokens", Value::Null),
        "truncation": "disabled",
        "output": [],
        "usage": null,
        "incomplete_details": null,
        "error": {
            "code": code,
            "message": message,
            "type": format!("upstream_http_{http_status}"),
            "upstream_error_kind": upstream_error_kind,
        },
    });
    let mut open_envelope = envelope.clone();
    open_envelope["status"] = json!("in_progress");
    open_envelope["error"] = Value::Null;

    let created_payload = json!({
        "type": "response.created",
        "sequence_number": sequence_number,
        "response": open_envelope.clone(),
    });
    sequence_number += 1;
    let in_progress_payload = json!({
        "type": "response.in_progress",
        "sequence_number": sequence_number,
        "response": open_envelope,
    });
    sequence_number += 1;
    envelope["error"]["upstream_error_kind"] = Value::String(upstream_error_kind.to_owned());
    let failed_payload = json!({
        "type": "response.failed",
        "sequence_number": sequence_number,
        "response": envelope,
    });

    let mut out = String::new();
    out.push_str("event: response.created\n");
    out.push_str("data: ");
    out.push_str(&created_payload.to_string());
    out.push_str("\n\n");
    out.push_str("event: response.in_progress\n");
    out.push_str("data: ");
    out.push_str(&in_progress_payload.to_string());
    out.push_str("\n\n");
    out.push_str("event: response.failed\n");
    out.push_str("data: ");
    out.push_str(&failed_payload.to_string());
    out.push_str("\n\n");
    out.into_bytes()
}

impl RequestMapper for ChatResponsesMapper {
    fn map_request(
        &self,
        client_path: &str,
        body: Bytes,
        provider: &Provider,
    ) -> Result<RequestPlan, AdapterError> {
        prepare_responses_request(client_path, body, provider)
    }
}

impl ResponseMapper for ChatResponsesMapper {
    fn map_response(
        &self,
        upstream_status: StatusCode,
        upstream_headers: HeaderMap,
        upstream_stream: ByteStream,
        provider: &Provider,
        request_plan: &RequestPlan,
    ) -> Result<ResponsePlan, AdapterError> {
        transform_responses_response_stream(
            upstream_status,
            upstream_headers,
            upstream_stream,
            provider,
            request_plan,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use indexmap::IndexMap;
    use serde_json::json;

    fn make_provider() -> Provider {
        Provider {
            id: "kimi-code".into(),
            name: "Kimi Code".into(),
            base_url: "https://api.kimi.com/coding/v1".into(),
            auth_scheme: "bearer".into(),
            api_format: "responses".into(),
            api_key: "sk-test".into(),
            models: IndexMap::new(),
            extra_headers: IndexMap::new(),
            model_capabilities: IndexMap::new(),
            request_options: IndexMap::new(),
            is_builtin: false,
            sort_index: 0,
            extra: IndexMap::new(),
        }
    }

    fn make_request_plan(history_lost: bool) -> RequestPlan {
        RequestPlan {
            upstream_path: "/chat/completions".into(),
            body: Bytes::from_static(br#"{"model":"kimi-for-coding"}"#),
            upstream_headers: HeaderMap::new(),
            response_session: None,
            adapter_metadata: if history_lost {
                Some(json!({"history_lost": true}))
            } else {
                None
            },
            is_compact: false,
            original_responses_request: Some(json!({
                "model": "kimi-for-coding",
                "tools": [],
                "tool_choice": "auto",
                "parallel_tool_calls": true,
                "reasoning": {"effort": "medium", "summary": null},
                "text": {"format": {"type":"text"}},
                "metadata": {"trace": "abc"},
                "previous_response_id": "resp_prev",
                "instructions": "help",
                "temperature": 0.2,
                "top_p": 0.9,
                "max_output_tokens": 1024
            })),
        }
    }

    fn collect_stream(stream: ByteStream) -> String {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let mut stream = stream;
            let mut all = Vec::new();
            while let Some(item) = stream.next().await {
                all.extend_from_slice(&item.unwrap());
            }
            String::from_utf8(all).unwrap()
        })
    }

    #[test]
    fn upstream_401_becomes_response_failed_invalid_prompt() {
        let upstream: ByteStream = Box::pin(stream::iter(vec![Ok(Bytes::from_static(
            br#"{"error":{"message":"API key invalid","status":"UNAUTHENTICATED"}}"#,
        ))]));
        let plan = transform_responses_response_stream(
            StatusCode::UNAUTHORIZED,
            HeaderMap::new(),
            upstream,
            &make_provider(),
            &make_request_plan(false),
        )
        .unwrap();

        assert_eq!(plan.status, StatusCode::OK);
        let out = collect_stream(plan.stream);
        assert!(out.contains("event: response.failed"));
        assert!(out.contains(r#""code":"invalid_prompt""#));
        assert!(out.contains(r#""upstream_error_kind":"auth_error""#));
        assert!(out.contains("API key invalid"));
    }

    #[test]
    fn upstream_429_preserves_retryable_semantics() {
        let upstream: ByteStream = Box::pin(stream::iter(vec![Ok(Bytes::from_static(
            br#"{"error":{"message":"Quota exceeded","status":"RESOURCE_EXHAUSTED"}}"#,
        ))]));
        let plan = transform_responses_response_stream(
            StatusCode::TOO_MANY_REQUESTS,
            HeaderMap::new(),
            upstream,
            &make_provider(),
            &make_request_plan(false),
        )
        .unwrap();

        let out = collect_stream(plan.stream);
        assert!(out.contains(r#""code":"quota_exceeded""#));
        assert!(out.contains(r#""upstream_error_kind":"quota_exceeded""#));
    }

    #[test]
    fn upstream_429_plain_text_quota_still_maps_to_quota_exceeded() {
        let upstream: ByteStream = Box::pin(stream::iter(vec![Ok(Bytes::from_static(
            b"quota exceeded for current plan",
        ))]));
        let plan = transform_responses_response_stream(
            StatusCode::TOO_MANY_REQUESTS,
            HeaderMap::new(),
            upstream,
            &make_provider(),
            &make_request_plan(false),
        )
        .unwrap();

        let out = collect_stream(plan.stream);
        assert!(out.contains(r#""code":"quota_exceeded""#));
        assert!(out.contains("quota exceeded for current plan"));
    }

    #[test]
    fn upstream_429_rate_limit_exceeded_stays_rate_limited() {
        let upstream: ByteStream = Box::pin(stream::iter(vec![Ok(Bytes::from_static(
            b"rate limit exceeded, retry later",
        ))]));
        let plan = transform_responses_response_stream(
            StatusCode::TOO_MANY_REQUESTS,
            HeaderMap::new(),
            upstream,
            &make_provider(),
            &make_request_plan(false),
        )
        .unwrap();

        let out = collect_stream(plan.stream);
        assert!(out.contains(r#""code":"rate_limited""#));
        assert!(out.contains(r#""upstream_error_kind":"rate_limited""#));
    }

    #[test]
    fn upstream_500_non_json_becomes_server_error() {
        let upstream: ByteStream = Box::pin(stream::iter(vec![Ok(Bytes::from_static(
            b"<html>Internal Server Error</html>",
        ))]));
        let plan = transform_responses_response_stream(
            StatusCode::INTERNAL_SERVER_ERROR,
            HeaderMap::new(),
            upstream,
            &make_provider(),
            &make_request_plan(false),
        )
        .unwrap();

        let out = collect_stream(plan.stream);
        assert!(out.contains(r#""code":"server_error""#));
        assert!(out.contains(r#""upstream_error_kind":"server_error""#));
        assert!(out.contains("HTTP 500"));
    }

    #[test]
    fn transport_error_still_emits_response_failed() {
        let upstream: ByteStream = Box::pin(stream::iter(vec![
            Ok(Bytes::from_static(br#"{"error":{"message":"partial"#)),
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "tcp reset by peer",
            )),
        ]));
        let plan = transform_responses_response_stream(
            StatusCode::TOO_MANY_REQUESTS,
            HeaderMap::new(),
            upstream,
            &make_provider(),
            &make_request_plan(false),
        )
        .unwrap();

        let out = collect_stream(plan.stream);
        assert!(out.contains("event: response.failed"));
        assert!(out.contains(r#""code":"rate_limited""#));
        assert!(out.contains(r#""upstream_error_kind":"transport_error""#));
        assert!(out.contains("tcp reset by peer"));
    }

    #[test]
    fn success_path_still_sets_event_stream_content_type() {
        let plan = transform_responses_response_stream(
            StatusCode::OK,
            HeaderMap::new(),
            Box::pin(stream::empty()),
            &make_provider(),
            &make_request_plan(false),
        )
        .unwrap();
        assert_eq!(plan.status, StatusCode::OK);
        assert_eq!(
            plan.headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/event-stream")
        );
    }

    #[test]
    fn history_lost_header_is_preserved_on_error_path() {
        let upstream: ByteStream = Box::pin(stream::iter(vec![Ok(Bytes::from_static(
            br#"{"error":{"message":"API key invalid","status":"UNAUTHENTICATED"}}"#,
        ))]));
        let plan = transform_responses_response_stream(
            StatusCode::UNAUTHORIZED,
            HeaderMap::new(),
            upstream,
            &make_provider(),
            &make_request_plan(true),
        )
        .unwrap();
        assert_eq!(plan.status, StatusCode::OK);
        assert_eq!(
            plan.headers
                .get("x-session-history-lost")
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
    }
}
