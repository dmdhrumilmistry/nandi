//! Human-in-the-loop approvals.
//!
//! A decision with verdict `Ask` parks the call here until an operator
//! approves or denies it (admin API, dashboard or CLI) or the timeout fires.
//! From the agent's point of view the call is just slow, so no client change
//! is needed (the Gravitee pattern). Timeouts resolve to the configured
//! verdict, which defaults to deny.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::oneshot;

use nandi_core::config::ApprovalConfig;
use nandi_core::util::{new_id, now_ms};
use nandi_core::{Decision, Event, Verdict};

use crate::client::{HttpClient, post_json};
use crate::metrics::Metrics;

#[derive(Debug, Clone, Serialize)]
pub struct Pending {
    pub id: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub agent: String,
    pub session: String,
    pub summary: String,
    pub event: Event,
    pub decision: Decision,
}

/// How a held call was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Approved,
    Denied,
    TimedOut,
}

struct Slot {
    pending: Pending,
    tx: oneshot::Sender<(bool, Option<String>)>,
}

pub struct ApprovalBroker {
    cfg: ApprovalConfig,
    slots: Mutex<HashMap<String, Slot>>,
    client: HttpClient,
    metrics: Arc<Metrics>,
}

impl ApprovalBroker {
    pub fn new(cfg: ApprovalConfig, client: HttpClient, metrics: Arc<Metrics>) -> Self {
        Self { cfg, slots: Mutex::new(HashMap::new()), client, metrics }
    }

    /// Hold the call until resolved. Returns the verdict to apply (`Allow`
    /// or `Deny`, or the timeout verdict) and how it was resolved.
    pub async fn request(&self, ev: &Event, d: &Decision) -> (Verdict, Resolution, Option<String>) {
        let id = new_id();
        let now = now_ms();
        let pending = Pending {
            id: id.clone(),
            created_ms: now,
            expires_ms: now + self.cfg.timeout_secs * 1000,
            agent: ev.agent.clone(),
            session: ev.session.clone(),
            summary: describe(ev, d),
            event: ev.clone(),
            decision: d.clone(),
        };
        let (tx, rx) = oneshot::channel();
        self.metrics.approvals_requested.fetch_add(1, Relaxed);
        if let Some(url) = &self.cfg.webhook {
            let body = serde_json::json!({
                "text": format!("nandi approval needed [{}]: {}", pending.id, pending.summary),
                "approval": &pending,
            });
            let (client, url) = (self.client.clone(), url.clone());
            tokio::spawn(async move {
                if let Err(e) = post_json(&client, &url, &[], &body).await {
                    tracing::warn!(error = %e, "approval webhook failed");
                }
            });
        }
        self.slots.lock().insert(id.clone(), Slot { pending, tx });

        let outcome = tokio::time::timeout(Duration::from_secs(self.cfg.timeout_secs), rx).await;
        self.slots.lock().remove(&id);
        match outcome {
            Ok(Ok((true, by))) => {
                self.metrics.approvals_granted.fetch_add(1, Relaxed);
                (Verdict::Allow, Resolution::Approved, by)
            }
            Ok(Ok((false, by))) => {
                self.metrics.approvals_denied.fetch_add(1, Relaxed);
                (Verdict::Deny, Resolution::Denied, by)
            }
            _ => {
                self.metrics.approvals_timed_out.fetch_add(1, Relaxed);
                let v = if self.cfg.on_timeout <= Verdict::Redact { Verdict::Allow } else { Verdict::Deny };
                (v, Resolution::TimedOut, None)
            }
        }
    }

    /// Resolve a held call. Returns false when the id is unknown or expired.
    pub fn resolve(&self, id: &str, approve: bool, by: Option<String>) -> bool {
        match self.slots.lock().remove(id) {
            Some(slot) => slot.tx.send((approve, by)).is_ok(),
            None => false,
        }
    }

    pub fn list(&self) -> Vec<Pending> {
        let mut v: Vec<Pending> = self.slots.lock().values().map(|s| s.pending.clone()).collect();
        v.sort_by_key(|p| p.created_ms);
        v
    }

    pub fn len(&self) -> usize {
        self.slots.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One-line description of a held action for humans.
pub fn describe(ev: &Event, d: &Decision) -> String {
    use nandi_core::EventKind::*;
    let what = match &ev.kind {
        ToolCall(c) => format!(
            "{} wants to call {}/{} with {}",
            ev.agent,
            c.server,
            c.tool,
            nandi_core::util::truncate(&c.args.to_string(), 300)
        ),
        A2aMessage(m) => format!("{} wants to send {} to agent {}", ev.agent, m.method, m.peer),
        LlmRequest(r) => format!("{} wants to call model {}/{}", ev.agent, r.provider, r.model),
        other => format!("{} event {}", ev.agent, other.name()),
    };
    format!("{what}; reason: {}", d.summary())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::{EventKind, Source, ToolCall};

    fn broker(timeout_secs: u64) -> Arc<ApprovalBroker> {
        let cfg = ApprovalConfig { timeout_secs, on_timeout: Verdict::Deny, webhook: None };
        Arc::new(ApprovalBroker::new(cfg, crate::client::build(), Arc::new(Metrics::new())))
    }

    fn ev() -> Event {
        Event::new(
            Source::Eval,
            "a",
            "s",
            EventKind::ToolCall(ToolCall {
                server: "bank".into(),
                tool: "pay".into(),
                call_id: None,
                args: serde_json::json!({"amount": 5}),
            }),
        )
    }

    #[tokio::test]
    async fn approve_and_deny() {
        let b = broker(30);
        for approve in [true, false] {
            let b2 = b.clone();
            let h = tokio::spawn(async move { b2.request(&ev(), &Decision::allow()).await });
            let id = loop {
                if let Some(p) = b.list().first() {
                    break p.id.clone();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            };
            assert!(b.list()[0].summary.contains("bank/pay"));
            assert!(b.resolve(&id, approve, Some("ops".into())));
            let (v, r, by) = h.await.unwrap();
            assert_eq!(v, if approve { Verdict::Allow } else { Verdict::Deny });
            assert_eq!(r, if approve { Resolution::Approved } else { Resolution::Denied });
            assert_eq!(by.as_deref(), Some("ops"));
        }
        assert!(b.is_empty());
        assert!(!b.resolve("nope", true, None));
    }

    #[tokio::test]
    async fn timeout_denies() {
        let b = broker(0);
        let (v, r, _) = b.request(&ev(), &Decision::allow()).await;
        assert_eq!((v, r), (Verdict::Deny, Resolution::TimedOut));
    }
}
