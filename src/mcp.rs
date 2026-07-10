//! Just enough MCP (Model Context Protocol) helpers for the proxy:
//! parsing `tools/call` and shaping tool results.

use serde_json::{json, Value};

/// Extract `(tool_name, arguments)` from a `tools/call` params object.
pub fn parse_tool_call(params: &Value) -> Option<(String, Value)> {
    let name = params.get("name")?.as_str()?.to_string();
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    Some((name, arguments))
}

/// An MCP tool result carrying text content (success).
pub fn tool_text_result(text: impl Into<String>) -> Value {
    json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": false
    })
}

/// An MCP tool result flagged as an error -- the agent sees a clean tool
/// failure rather than a transport error.
pub fn tool_error_result(text: impl Into<String>) -> Value {
    json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": true
    })
}

/// True if a `tools/call` result is an MCP tool error.
pub fn result_is_tool_error(result: &Value) -> bool {
    result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}
