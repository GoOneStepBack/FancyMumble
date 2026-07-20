//! Inbound decoding for the audit plugin, tunnelled over the generic
//! plugin-message channel (`PluginMessage`, wire ID 200).
//!
//! The plugin is fully opaque to the server: it speaks JSON payloads
//! (`audit.result`, `audit.verify.result`, `audit.config`) stamped with the
//! `fancy-audit` plugin name. We decode them here and re-emit the same
//! `audit-response` / `audit-config` Tauri events the admin panel already
//! listens to, so nothing above the transport changes. Correlation ids ride in
//! the JSON body (`request_id`) rather than a dedicated wire field.

use serde::Serialize;
use serde_json::Value;

use super::HandlerContext;
use crate::state::types::{AuditConfigSnapshot, AuditEntryPayload, ServerSetting};

/// Payload for the `audit-response` event (query results and chain-verify
/// outcomes share it, matching the frontend store's single applier).
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct AuditResponsePayload {
    query_id: Option<String>,
    entries: Vec<AuditEntryPayload>,
    has_more: bool,
    next_before_id: Option<u64>,
    error: Option<String>,
    chain_ok: Option<bool>,
    chain_height: Option<u64>,
    chain_error: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct AuditConfigPayload {
    config: AuditConfigSnapshot,
}

/// Dispatch one inbound audit payload by its plugin `payload_type`. Returns
/// `true` if it was an audit payload we recognised (so the caller skips the
/// generic `plugin-message` fan-out for it).
pub(super) fn handle_audit_payload(
    ctx: &HandlerContext,
    payload_type: &str,
    payload: &[u8],
) -> bool {
    let is_audit = matches!(
        payload_type,
        "audit.result" | "audit.verify.result" | "audit.config"
    );
    if !is_audit {
        return false;
    }
    // A malformed body is still an audit payload we "own"; drop it rather than
    // leaking it out as a generic plugin-message event.
    let Ok(value) = serde_json::from_slice::<Value>(payload) else {
        return true;
    };
    match payload_type {
        "audit.result" => emit_result(ctx, &value),
        "audit.verify.result" => emit_verify(ctx, &value),
        "audit.config" => emit_config(ctx, &value),
        _ => {}
    }
    true
}

fn request_id(v: &Value) -> Option<String> {
    v.get("request_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn emit_result(ctx: &HandlerContext, v: &Value) {
    let entries = v
        .get("entries")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(decode_entry).collect())
        .unwrap_or_default();
    ctx.emit(
        "audit-response",
        AuditResponsePayload {
            query_id: request_id(v),
            entries,
            has_more: v.get("has_more").and_then(Value::as_bool).unwrap_or(false),
            next_before_id: v.get("next_before_id").and_then(Value::as_u64),
            error: v
                .get("error")
                .and_then(Value::as_str)
                .filter(|e| !e.is_empty())
                .map(str::to_owned),
            chain_ok: None,
            chain_height: None,
            chain_error: None,
        },
    );
}

fn emit_verify(ctx: &HandlerContext, v: &Value) {
    let intact = v.get("intact").and_then(Value::as_bool);
    // `checked` on an intact chain, `index` on a broken one, is the height.
    let height = v
        .get("checked")
        .or_else(|| v.get("index"))
        .and_then(Value::as_u64);
    let chain_error = if intact == Some(false) {
        v.get("description")
            .or_else(|| v.get("kind"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    } else {
        v.get("error").and_then(Value::as_str).map(str::to_owned)
    };
    // The frontend keys its chain-status branch on `chainOk` OR `chainError`
    // being present; an `error`-only reply (no `intact`) must still report, so
    // synthesise `chainOk = false` for it.
    let chain_ok = intact.or_else(|| chain_error.as_ref().map(|_| false));
    ctx.emit(
        "audit-response",
        AuditResponsePayload {
            query_id: request_id(v),
            entries: Vec::new(),
            has_more: false,
            next_before_id: None,
            error: None,
            chain_ok,
            chain_height: height,
            chain_error: chain_error.filter(|e| !e.is_empty()),
        },
    );
}

fn emit_config(ctx: &HandlerContext, v: &Value) {
    let settings = v
        .get("settings")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(decode_setting).collect())
        .unwrap_or_default();
    let snapshot = AuditConfigSnapshot {
        settings,
        revision: v.get("revision").and_then(Value::as_u64).unwrap_or(0),
        advanced_sql_available: v
            .get("advanced_sql_available")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        chain_height: v.get("chain_height").and_then(Value::as_u64).unwrap_or(0),
        sql_schema_json: v
            .get("sql_schema_json")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
    };
    if let Ok(mut state) = ctx.shared.lock() {
        // Only accept newer (or equal) revisions so a stale reply can't clobber
        // a fresher local view after an admin edit.
        let accept = state
            .audit_config
            .as_ref()
            .is_none_or(|prev| snapshot.revision >= prev.revision);
        if !accept {
            return;
        }
        state.audit_config = Some(snapshot.clone());
    }
    ctx.emit("audit-config", AuditConfigPayload { config: snapshot });
}

/// Decode one generic `Setting` row from the plugin's config snapshot.
fn decode_setting(v: &Value) -> ServerSetting {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    ServerSetting {
        key: s("key").unwrap_or_default(),
        r#type: s("type").unwrap_or_else(|| "string".to_owned()),
        group: s("group").unwrap_or_default(),
        label: s("label").unwrap_or_default(),
        value: s("value"),
        options: v
            .get("options")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
            .unwrap_or_default(),
        secret: v.get("secret").and_then(Value::as_bool).unwrap_or(false),
        help: s("help"),
    }
}

/// Decode one audit entry from the plugin's compact JSON shape (`entry_hash`
/// arrives as a hex string; identity fields are nested under `actor`/`target`).
fn decode_entry(v: &Value) -> AuditEntryPayload {
    let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    let u = |k: &str| v.get(k).and_then(Value::as_u64);
    let ident_u = |obj: &str, k: &str| {
        v.get(obj)
            .and_then(|o| o.get(k))
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    };
    let ident_s = |obj: &str, k: &str| {
        v.get(obj)
            .and_then(|o| o.get(k))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    AuditEntryPayload {
        id: u("id").unwrap_or(0),
        ts: v.get("ts_ms").and_then(Value::as_u64).or_else(|| u("ts")).unwrap_or(0),
        source: s("source").unwrap_or_default(),
        category: s("category").unwrap_or_default(),
        severity: s("severity").unwrap_or_else(|| "info".to_owned()),
        actor_user_id: ident_u("actor", "user_id"),
        actor_hash: ident_s("actor", "hash"),
        actor_name: ident_s("actor", "name"),
        target_user_id: ident_u("target", "user_id"),
        target_hash: ident_s("target", "hash"),
        target_name: ident_s("target", "name"),
        channel_id: u("channel_id").and_then(|n| u32::try_from(n).ok()),
        reason: s("reason"),
        detail_json: s("detail_json"),
        relates_to: u("relates_to"),
        entry_hash: s("entry_hash").filter(|h| !h.is_empty()),
    }
}
