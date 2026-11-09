//! Asynchronous sink for evaluated events.
//!
//! Capture points hand every (event, decision) to [`Recorder::record`],
//! which never blocks: entries go into a bounded queue and a background task
//! batches them into the audit log, the live event stream (dashboard / SSE),
//! OTLP and webhooks. When the queue is full entries are dropped and counted
//! rather than slowing the agent down.

use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{broadcast, mpsc};

use nandi_audit::AuditLog;
use nandi_core::config::{AuditConfig, TelemetryConfig, resolve_secret};
use nandi_core::{Decision, Event, Verdict};

use crate::client::{HttpClient, post_json};
use crate::metrics::Metrics;
use crate::otlp;

const QUEUE: usize = 8192;
const BATCH: usize = 256;

/// One evaluated event as published to live subscribers.
#[derive(Debug, Clone, Serialize)]
pub struct LiveEvent {
    /// Audit sequence number when the event was persisted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    pub event: Event,
    pub decision: Decision,
    /// Verdict actually applied (after monitor mode and approvals).
    pub applied: Verdict,
}

struct Entry {
    event: Event,
    decision: Decision,
    applied: Verdict,
    eval_ns: u64,
}

#[derive(Clone)]
pub struct Recorder {
    tx: mpsc::Sender<Entry>,
    live: broadcast::Sender<Arc<LiveEvent>>,
    metrics: Arc<Metrics>,
}

impl Recorder {
    /// Start the background task. `audit` is optional (disabled or tests).
    pub fn start(
        audit: Option<Arc<AuditLog>>,
        audit_cfg: AuditConfig,
        telemetry: TelemetryConfig,
        client: HttpClient,
        metrics: Arc<Metrics>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE);
        let (live, _) = broadcast::channel(1024);
        let worker = Worker { audit, audit_cfg, telemetry, client, metrics: metrics.clone(), live: live.clone() };
        tokio::spawn(worker.run(rx));
        Self { tx, live, metrics }
    }

    /// Queue an evaluated event. Never blocks.
    pub fn record(&self, event: Event, decision: Decision, applied: Verdict, eval_ns: u64) {
        if self.tx.try_send(Entry { event, decision, applied, eval_ns }).is_err() {
            self.metrics.recorder_dropped.fetch_add(1, Relaxed);
        }
    }

    /// Subscribe to the live stream (dashboard, `nandi tail`).
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LiveEvent>> {
        self.live.subscribe()
    }
}

struct Worker {
    audit: Option<Arc<AuditLog>>,
    audit_cfg: AuditConfig,
    telemetry: TelemetryConfig,
    client: HttpClient,
    metrics: Arc<Metrics>,
    live: broadcast::Sender<Arc<LiveEvent>>,
}

impl Worker {
    async fn run(self, mut rx: mpsc::Receiver<Entry>) {
        let otlp_headers: Vec<(String, String)> = self
            .telemetry
            .otlp_headers
            .iter()
            .filter_map(|(k, v)| resolve_secret(v).ok().map(|v| (k.clone(), v)))
            .collect();
        let mut buf: Vec<Entry> = Vec::with_capacity(BATCH);
        loop {
            let n = rx.recv_many(&mut buf, BATCH).await;
            if n == 0 {
                break;
            }
            // Let a burst accumulate briefly so audit writes are batched.
            if buf.len() < BATCH {
                tokio::time::sleep(Duration::from_millis(20)).await;
                while buf.len() < BATCH {
                    match rx.try_recv() {
                        Ok(e) => buf.push(e),
                        Err(_) => break,
                    }
                }
            }
            let batch = std::mem::take(&mut buf);
            self.flush(batch, &otlp_headers).await;
        }
    }

    async fn flush(&self, batch: Vec<Entry>, otlp_headers: &[(String, String)]) {
        let mut seqs: Vec<Option<u64>> = vec![None; batch.len()];
        if let Some(audit) = &self.audit {
            let items: Vec<(usize, (Event, Decision))> = batch
                .iter()
                .enumerate()
                .filter(|(_, e)| self.audit_cfg.record_clean || !e.decision.findings.is_empty())
                .map(|(i, e)| (i, (e.event.clone(), e.decision.clone())))
                .collect();
            if !items.is_empty() {
                let audit = audit.clone();
                let (idx, pairs): (Vec<usize>, Vec<(Event, Decision)>) = items.into_iter().unzip();
                match tokio::task::spawn_blocking(move || audit.append_batch(&pairs)).await {
                    Ok(Ok(records)) => {
                        for (i, r) in idx.into_iter().zip(records) {
                            seqs[i] = Some(r.seq);
                        }
                    }
                    Ok(Err(e)) => {
                        self.metrics.audit_errors.fetch_add(1, Relaxed);
                        tracing::error!(error = %e, "audit append failed");
                    }
                    Err(e) => {
                        self.metrics.audit_errors.fetch_add(1, Relaxed);
                        tracing::error!(error = %e, "audit task failed");
                    }
                }
            }
        }

        let mut spans = Vec::new();
        let mut alerts = Vec::new();
        for (entry, seq) in batch.into_iter().zip(seqs) {
            if self.telemetry.otlp_endpoint.is_some() {
                spans.push(otlp::span(&entry.event, &entry.decision, entry.applied, entry.eval_ns));
            }
            if !self.telemetry.webhooks.is_empty()
                && entry.decision.findings.iter().any(|f| f.severity >= self.telemetry.webhook_min_severity)
            {
                alerts.push(serde_json::json!({
                    "text": format!(
                        "nandi {} for {}: {}",
                        entry.applied.as_str(),
                        entry.event.agent,
                        entry.decision.summary()
                    ),
                    "event": &entry.event,
                    "decision": &entry.decision,
                    "applied": entry.applied,
                }));
            }
            if !entry.decision.findings.is_empty() {
                tracing::info!(
                    agent = %entry.event.agent,
                    kind = entry.event.kind_name(),
                    verdict = entry.decision.verdict.as_str(),
                    applied = entry.applied.as_str(),
                    "{}",
                    entry.decision.summary()
                );
            }
            let _ = self.live.send(Arc::new(LiveEvent {
                seq,
                event: entry.event,
                decision: entry.decision,
                applied: entry.applied,
            }));
        }

        if let Some(endpoint) = &self.telemetry.otlp_endpoint
            && !spans.is_empty()
        {
            let url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
            let body = otlp::export_request(&self.telemetry.service_name, spans);
            if let Err(e) = post_json(&self.client, &url, otlp_headers, &body).await {
                tracing::warn!(error = %e, "OTLP export failed");
            }
        }
        for alert in alerts {
            for url in &self.telemetry.webhooks {
                let (client, url, alert) = (self.client.clone(), url.clone(), alert.clone());
                tokio::spawn(async move {
                    if let Err(e) = post_json(&client, &url, &[], &alert).await {
                        tracing::warn!(error = %e, "webhook failed");
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::{EventKind, Source, ToolCall};

    #[tokio::test]
    async fn records_to_audit_and_live_stream() {
        let audit = Arc::new(AuditLog::open_in_memory().unwrap());
        let metrics = Arc::new(Metrics::new());
        let rec = Recorder::start(
            Some(audit.clone()),
            AuditConfig::default(),
            TelemetryConfig::default(),
            crate::client::build(),
            metrics,
        );
        let mut live = rec.subscribe();
        let ev = Event::new(
            Source::Eval,
            "a",
            "s",
            EventKind::ToolCall(ToolCall {
                server: "x".into(),
                tool: "y".into(),
                call_id: None,
                args: Default::default(),
            }),
        );
        rec.record(ev.clone(), Decision::allow(), Verdict::Allow, 1000);
        let got = tokio::time::timeout(Duration::from_secs(5), live.recv()).await.unwrap().unwrap();
        assert_eq!(got.event.id, ev.id);
        assert_eq!(got.seq, Some(1));
        assert_eq!(audit.len().unwrap(), 1);
    }
}
