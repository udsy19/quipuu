//! `get_scan_results` verb — cursor-paginated retrieval from session store.
//!
//! Used by the streaming fallback: after `scan_source` returns a `scanId` in
//! streaming mode, the client calls `get_scan_results` with the cursor to page
//! through findings.
//!
//! Params:
//!   scanId?: string    — the scan to page (alternative to providing a cursor)
//!   cursor?: string    — opaque cursor from a previous response
//!   pageSize?: number  — max findings per page (default 50, max 500)

use cryptoscope_core::load_builtins;
use serde_json::{Value, json};

use crate::mcp::errors::{E_CURSOR_INVALID, E_RULESET_INVALID, E_SCAN_NOT_FOUND};
use crate::mcp::session::{SessionStore, decode_cursor, encode_cursor, finding_with_risk_to_json};

const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 500;

pub fn handle(params: Option<Value>, session: &SessionStore) -> Result<Value, (i32, String)> {
    let params = params.unwrap_or(Value::Null);

    let page_size = params
        .get("pageSize")
        .and_then(Value::as_u64)
        .map(|n| (n as usize).min(MAX_PAGE_SIZE))
        .unwrap_or(DEFAULT_PAGE_SIZE);

    // Resolve (scan_id, offset) from either cursor or scanId.
    let (scan_id, offset) = if let Some(cursor_str) = params.get("cursor").and_then(Value::as_str) {
        decode_cursor(cursor_str)
            .ok_or_else(|| (E_CURSOR_INVALID, format!("invalid cursor: {cursor_str}")))?
    } else if let Some(sid) = params.get("scanId").and_then(Value::as_str) {
        (sid, 0usize)
    } else {
        return Err((
            E_SCAN_NOT_FOUND,
            "either params.cursor or params.scanId is required".to_string(),
        ));
    };

    let stored = session
        .get(scan_id)
        .ok_or_else(|| (E_SCAN_NOT_FOUND, format!("scanId not found: {scan_id}")))?;

    let total = stored.findings.len();
    // The cursor is client-supplied and decode_cursor accepts any usize, so
    // both bounds must be clamped. Slicing on a raw offset panicked the MCP
    // server — which the transport loop is explicitly designed never to do —
    // and `offset + page_size` could overflow on a large cursor.
    let offset = offset.min(total);
    let end = offset.saturating_add(page_size).min(total);
    let page = &stored.findings[offset..end];

    let has_more = end < total;
    let next_cursor = if has_more {
        Some(encode_cursor(scan_id, end))
    } else {
        None
    };

    let builtins = load_builtins().map_err(|e| (E_RULESET_INVALID, e.to_string()))?;
    let findings_json: Vec<Value> = page
        .iter()
        .map(|f| finding_with_risk_to_json(f, &builtins.algorithms, &builtins.policy))
        .collect();

    Ok(json!({
        "scanId": scan_id,
        "findings": findings_json,
        "offset": offset,
        "returned": page.len(),
        "total": total,
        "hasMore": has_more,
        "nextCursor": next_cursor,
        "deterministic": stored.deterministic,
        "provenance": "deterministic",
    }))
}
