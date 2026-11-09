//! Shared application state used by every capture point.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;

use nandi_audit::AuditLog;
use nandi_core::{Config, Decision, Event, StateStore, Verdict};
use nandi_engine::{Classifier, Engine};
use nandi_identity::Authenticator;
use nandi_identity::card::TrustedKeys;
use nandi_policy::PolicySet;

use crate::approvals::{ApprovalBroker, Resolution};
use crate::client::{self, HttpClient};
use crate::metrics::Metrics;
use crate::recorder::Recorder;

/// Final outcome of [`App::decide`].
#[derive(Debug, Clone)]
pub struct Verdicted {
    pub decision: Decision,
    /// Verdict to apply: `Allow`, `Alert`, `Redact` or `Deny` (never `Ask`;
    /// held calls are resolved before returning).
    pub applied: Verdict,
    pub approval: Option<Resolution>,
}

impl Verdicted {
    pub fn blocked(&self) -> bool {
        self.applied == Verdict::Deny
    }

    /// Replacement payload to apply, if any (only when enforced).
    pub fn rewrite(&self) -> Option<&serde_json::Value> {
        if self.decision.enforced && !self.blocked() { self.decision.rewrite.as_ref() } else { None }
    }

    /// Message suitable for returning to the agent when blocked.
    pub fn reason(&self) -> String {
        match self.approval {
            Some(Resolution::Denied) => format!("denied by an operator: {}", self.decision.summary()),
            Some(Resolution::TimedOut) => format!("approval timed out: {}", self.decision.summary()),
            _ => self.decision.summary(),
        }
    }
}

pub struct App {
    pub cfg: Config,
    /// Directory relative config paths are resolved against.
    pub base_dir: PathBuf,
    pub engine: Arc<Engine>,
    pub auth: Authenticator,
    pub audit: Option<Arc<AuditLog>>,
    pub approvals: ApprovalBroker,
    pub recorder: Recorder,
    pub metrics: Arc<Metrics>,
    pub client: HttpClient,
    pub card_keys: TrustedKeys,
    pub started: Instant,
}

impl App {
    /// Build from a loaded config. `base_dir` is the config file's directory.
    pub fn build(cfg: Config, base_dir: &Path, classifier: Option<Arc<dyn Classifier>>) -> anyhow::Result<Arc<App>> {
        let data_dir = resolve(base_dir, &cfg.data_dir());
        std::fs::create_dir_all(&data_dir).with_context(|| format!("creating {}", data_dir.display()))?;
        let db = resolve(base_dir, &cfg.audit.path.clone().unwrap_or_else(|| data_dir.join("audit.redb")));
        let key = resolve(base_dir, &cfg.audit.signing_key.clone().unwrap_or_else(|| data_dir.join("audit.key")));
        let log = Arc::new(AuditLog::open(&db, &key).with_context(|| format!("opening {}", db.display()))?);
        let store: Arc<dyn StateStore> = log.clone();
        let policy = PolicySet::load(&cfg.policy, base_dir).context("loading policy")?;
        for warning in policy.validate() {
            tracing::warn!("policy: {warning}");
        }
        let audit = cfg.audit.enabled.then_some(log);
        Self::assemble(cfg, base_dir, policy, store, audit, classifier)
    }

    /// In-memory app for tests and evaluation runs.
    pub fn ephemeral(cfg: Config, policy: PolicySet) -> anyhow::Result<Arc<App>> {
        let store: Arc<dyn StateStore> = Arc::new(nandi_core::MemoryStore::new());
        Self::assemble(cfg, Path::new("."), policy, store, None, None)
    }

    fn assemble(
        cfg: Config,
        base_dir: &Path,
        policy: PolicySet,
        store: Arc<dyn StateStore>,
        audit: Option<Arc<AuditLog>>,
        classifier: Option<Arc<dyn Classifier>>,
    ) -> anyhow::Result<Arc<App>> {
        let mut engine = Engine::new(cfg.clone(), policy, store);
        if let Some(c) = classifier {
            engine = engine.with_classifier(c);
        }
        let auth = Authenticator::new(&cfg.identity, base_dir).context("loading identity config")?;
        let key_paths: Vec<PathBuf> = cfg.a2a.trusted_keys.iter().map(|p| resolve(base_dir, p)).collect();
        let card_keys = TrustedKeys::load(&key_paths).context("loading A2A trusted keys")?;
        let client = client::build();
        let metrics = Arc::new(Metrics::new());
        let recorder =
            Recorder::start(audit.clone(), cfg.audit.clone(), cfg.telemetry.clone(), client.clone(), metrics.clone());
        let approvals = ApprovalBroker::new(cfg.approvals.clone(), client.clone(), metrics.clone());
        let app = Arc::new(App {
            base_dir: base_dir.to_path_buf(),
            engine: Arc::new(engine),
            auth,
            audit,
            approvals,
            recorder,
            metrics,
            client,
            card_keys,
            started: Instant::now(),
            cfg,
        });
        app.clone().spawn_housekeeping();
        Ok(app)
    }

    /// Evaluate an event, hold it for approval if needed, record it, and
    /// return the verdict to apply.
    pub async fn decide(&self, ev: Event, groups: &[String]) -> Verdicted {
        let t = Instant::now();
        let decision = self.engine.evaluate(&ev, groups);
        let eval_ns = t.elapsed().as_nanos() as u64;
        self.metrics.observe(&ev, &decision, eval_ns / 1000);
        let (applied, approval) = match decision.effective() {
            Verdict::Ask => {
                let (v, r, by) = self.approvals.request(&ev, &decision).await;
                if let Some(by) = by {
                    tracing::info!(agent = %ev.agent, approver = %by, resolution = ?r, "approval resolved");
                }
                (v, Some(r))
            }
            v => (v, None),
        };
        self.recorder.record(ev, decision.clone(), applied, eval_ns);
        Verdicted { decision, applied, approval }
    }

    /// Reload policy files from disk and swap them in.
    pub fn reload_policy(&self) -> anyhow::Result<Vec<String>> {
        let policy = PolicySet::load(&self.cfg.policy, &self.base_dir)?;
        let warnings = policy.validate();
        self.engine.set_policy(policy);
        Ok(warnings)
    }

    fn spawn_housekeeping(self: Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
        let weak = Arc::downgrade(&self);
        drop(self);
        handle.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            let mut n: u64 = 0;
            loop {
                tick.tick().await;
                let Some(app) = weak.upgrade() else { break };
                app.engine.flush();
                n += 1;
                // Hourly retention sweep.
                if n.is_multiple_of(120)
                    && let Some(audit) = &app.audit
                    && app.cfg.audit.retention_days > 0
                {
                    let cutoff =
                        nandi_core::util::now_ms().saturating_sub(app.cfg.audit.retention_days as u64 * 86_400_000);
                    let audit = audit.clone();
                    let _ = tokio::task::spawn_blocking(move || audit.prune_older_than(cutoff)).await;
                }
            }
        });
    }

    /// Persist learned state now (shutdown).
    pub fn shutdown(&self) {
        self.engine.flush();
    }
}

/// Resolve `p` against `base` unless it is absolute.
pub fn resolve(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() { p.to_path_buf() } else { base.join(p) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::config::Mode;
    use nandi_core::{EventKind, Source, ToolCall};

    #[tokio::test]
    async fn decide_applies_monitor_and_enforce() {
        let rules = "rules:\n  - id: no-exec\n    match: { tool: 'exec*' }\n    action: deny\n";
        let call = || {
            Event::new(
                Source::Eval,
                "a",
                "s",
                EventKind::ToolCall(ToolCall {
                    server: "sys".into(),
                    tool: "exec".into(),
                    call_id: None,
                    args: serde_json::json!({}),
                }),
            )
        };
        let policy = || PolicySet::from_sources(Default::default(), None, None, &[rules]).unwrap();
        let app = App::ephemeral(Config::default(), policy()).unwrap();
        let v = app.decide(call(), &[]).await;
        assert_eq!(v.decision.verdict, Verdict::Deny);
        assert_eq!(v.applied, Verdict::Allow);

        let app = App::ephemeral(Config { mode: Mode::Enforce, ..Config::default() }, policy()).unwrap();
        let v = app.decide(call(), &[]).await;
        assert!(v.blocked());
        assert!(v.reason().contains("no-exec"));
    }

    #[tokio::test]
    async fn build_creates_data_dir_and_audit() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config { data_dir: Some(dir.path().join("data")), ..Config::default() };
        let app = App::build(cfg, dir.path(), None).unwrap();
        assert!(dir.path().join("data/audit.key").exists());
        assert!(app.audit.is_some());
    }
}
