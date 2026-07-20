//! Audit-log methods on `AppState`.
//!
//! The audit plugin is fully opaque to the server: all audit traffic rides the
//! generic plugin-message channel (`PluginMessage`, wire ID 200) as JSON,
//! addressed to the `fancy-audit` plugin by name. Each request carries a
//! `request_id` the plugin echoes into its reply so the frontend can correlate
//! them; replies arrive as inbound `PluginMessage`s decoded in
//! [`super::handler::audit`] into the same `audit-response` / `audit-config`
//! Tauri events the admin panel already consumes.

use mumble_protocol::command;
use serde_json::json;

use super::types::{AuditConfigSnapshot, AuditQueryArgs, ServerSetting};
use super::AppState;

/// Wire name of the audit plugin (its `MumblePlugin::name`).
const AUDIT_PLUGIN: &str = "fancy-audit";

impl AppState {
    /// Snapshot the cached audit configuration, if any.
    pub fn get_audit_config(&self) -> Option<AuditConfigSnapshot> {
        let snapshot = self.inner.snapshot();
        let guard = snapshot.lock().ok()?;
        guard.audit_config.clone()
    }

    /// Send an audit query or a hash-chain verification to the plugin.
    ///
    /// A `verify_chain` request maps to the plugin's `audit.verify` op (it
    /// carries no row filter and returns only the chain outcome); every other
    /// query maps to `audit.query`. Both replies come back over the generic
    /// plugin-message channel as `audit.result` / `audit.verify.result`.
    pub async fn query_audit_log(&self, args: AuditQueryArgs) -> Result<(), String> {
        let request_id = args.query_id.clone().unwrap_or_default();
        let (payload_type, body) = if args.verify_chain.unwrap_or(false) {
            ("audit.verify", json!({ "request_id": request_id }))
        } else {
            (
                "audit.query",
                json!({
                    "request_id": request_id,
                    "categories": args.categories,
                    "source": args.source,
                    "actor_user_id": args.actor_user_id,
                    "target_user_id": args.target_user_id,
                    "channel_id": args.channel_id,
                    "text": args.text,
                    "since_ms": args.since_ms,
                    "until_ms": args.until_ms,
                    "before_id": args.before_id,
                    "limit": args.limit,
                }),
            )
        };
        self.send_audit(payload_type, &body).await
    }

    /// Request a fresh configuration snapshot (`audit.config.get`). The reply
    /// arrives as an `audit-config` event. Called when the Audit tab opens,
    /// replacing the old server-initiated config push (the server no longer
    /// knows the audit feature exists).
    pub async fn request_audit_config(&self) -> Result<(), String> {
        self.send_audit("audit.config.get", &json!({ "request_id": "" }))
            .await
    }

    /// Audit-admin path: apply changed toggles (`audit.config.set`). Only the
    /// `key` and `value` of each setting are sent; the rest of the schema is
    /// owned by the audit plugin. The plugin replies with the fresh snapshot.
    pub async fn save_audit_config(&self, changed: Vec<ServerSetting>) -> Result<(), String> {
        let settings: Vec<_> = changed
            .iter()
            .map(|s| json!({ "key": s.key, "value": s.value }))
            .collect();
        self.send_audit(
            "audit.config.set",
            &json!({ "request_id": "", "settings": settings }),
        )
        .await
    }

    /// Encode `body` as JSON and deliver it to the audit plugin over the
    /// generic plugin-message channel (server-bound: no target sessions, so the
    /// host consumes it rather than relaying it to other clients).
    async fn send_audit(
        &self,
        payload_type: &str,
        body: &serde_json::Value,
    ) -> Result<(), String> {
        let handle = {
            let session = self.inner.snapshot();
            let state = session.lock().map_err(|e| e.to_string())?;
            state.conn.client_handle.clone()
        };
        let handle = handle.ok_or("Not connected")?;
        let payload = serde_json::to_vec(body).map_err(|e| e.to_string())?;
        handle
            .send(command::SendPluginMessage {
                plugin_name: AUDIT_PLUGIN.to_owned(),
                payload_type: payload_type.to_owned(),
                payload,
                target_sessions: Vec::new(),
                channel_id: None,
            })
            .await
            .map_err(|e| format!("Failed to send audit message: {e}"))?;
        Ok(())
    }
}
