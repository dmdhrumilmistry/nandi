//! Commands that work on files without a running nandi: policy validation,
//! policy tests, replay and audit log maintenance.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde_json::{Value, json};

use nandi_audit::{AuditLog, Query, verify_jsonl};
use nandi_core::util::{new_id, now_ms};
use nandi_core::{Config, Decision, Event};
use nandi_engine::Engine;
use nandi_gateway::app::resolve;
use nandi_policy::PolicySet;

use crate::remote::{rules_of, target};

/// Load the policy files named in the config.
pub fn load_policy(cfg: &Config, base: &Path) -> anyhow::Result<PolicySet> {
    PolicySet::load(&cfg.policy, base).map_err(|e| anyhow::anyhow!("{e}"))
}

/// `nandi policy validate`.
pub fn validate(cfg: &Config, base: &Path) -> anyhow::Result<()> {
    let policy = load_policy(cfg, base)?;
    let warnings = policy.validate();
    for w in &warnings {
        println!("warning: {w}");
    }
    println!(
        "ok: {} rule file(s), {} Cedar file(s), default {:?}, {} warning(s)",
        cfg.policy.rules.len(),
        cfg.policy.cedar.len(),
        policy.default_action(),
        warnings.len()
    );
    Ok(())
}

/// Parse one test-file line: an [`Event`] (missing `id`, `ts_ms`, `source`,
/// `agent` and `session` are filled in) or `{"event": ..., "groups": [...]}`.
pub fn parse_test_line(line: &str) -> anyhow::Result<(Event, Vec<String>)> {
    let v: Value = serde_json::from_str(line).context("invalid JSON")?;
    let (mut ev, groups) = match v.get("event") {
        Some(ev) => {
            let groups = match v.get("groups") {
                Some(g) => serde_json::from_value(g.clone()).context("`groups` must be a list of strings")?,
                None => Vec::new(),
            };
            (ev.clone(), groups)
        }
        None => (v, Vec::new()),
    };
    let obj = ev.as_object_mut().context("event must be a JSON object")?;
    obj.entry("id").or_insert_with(|| json!(new_id()));
    obj.entry("ts_ms").or_insert_with(|| json!(now_ms()));
    obj.entry("source").or_insert_with(|| json!("eval"));
    obj.entry("agent").or_insert_with(|| json!("test-agent"));
    obj.entry("session").or_insert_with(|| json!("test-session"));
    let ev: Event = serde_json::from_value(ev).context("not a valid event")?;
    Ok((ev, groups))
}

fn rules(d: &Decision) -> Vec<String> {
    d.findings.iter().map(|f| f.rule.clone()).collect()
}

/// `nandi policy test`: evaluate events in order with a fresh engine.
pub fn test(cfg: &Config, base: &Path, events: &Path, json_out: bool) -> anyhow::Result<()> {
    let policy = load_policy(cfg, base)?;
    let engine = Engine::ephemeral(cfg.clone(), policy);
    let file = File::open(events).with_context(|| format!("opening {}", events.display()))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let (ev, groups) = parse_test_line(trimmed).with_context(|| format!("{}:{}", events.display(), i + 1))?;
        let d = engine.evaluate(&ev, &groups);
        let ev_json = serde_json::to_value(&ev)?;
        if json_out {
            let row = json!({
                "line": i + 1,
                "kind": ev.kind_name(),
                "target": target(&ev_json),
                "verdict": d.verdict,
                "rules": rules(&d),
                "summary": d.summary(),
            });
            writeln!(out, "{row}")?;
        } else {
            writeln!(
                out,
                "{:<4} {:<13} {:<32} {:<6} {}",
                i + 1,
                ev.kind_name(),
                target(&ev_json),
                d.verdict.as_str(),
                rules(&d).join(",")
            )?;
        }
    }
    Ok(())
}

/// Default audit database and key paths from the config.
pub fn audit_paths(cfg: &Config, base: &Path, db: Option<PathBuf>, key: Option<PathBuf>) -> (PathBuf, PathBuf) {
    let data = resolve(base, &cfg.data_dir());
    let db = db.unwrap_or_else(|| resolve(base, &cfg.audit.path.clone().unwrap_or_else(|| data.join("audit.redb"))));
    let key =
        key.unwrap_or_else(|| resolve(base, &cfg.audit.signing_key.clone().unwrap_or_else(|| data.join("audit.key"))));
    (db, key)
}

/// Open an existing audit log. Refuses to create files: a missing key would
/// otherwise be generated and every signature would look forged.
pub fn open_audit(db: &Path, key: &Path) -> anyhow::Result<AuditLog> {
    if !db.exists() {
        bail!("audit database {} does not exist", db.display());
    }
    if !key.exists() {
        bail!("audit key {} does not exist", key.display());
    }
    AuditLog::open(db, key).map_err(|e| {
        anyhow::anyhow!("opening {}: {e} (is `nandi run` using it? stop it or use an exported copy)", db.display())
    })
}

/// Counts printed at the end of a replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplaySummary {
    pub total: usize,
    pub changed: usize,
    pub stricter: usize,
}

/// `nandi replay`: re-evaluate recorded events with the current policy.
pub fn replay(
    cfg: &Config,
    base: &Path,
    log: &AuditLog,
    since_seq: u64,
    limit: usize,
    json_out: bool,
) -> anyhow::Result<ReplaySummary> {
    let policy = load_policy(cfg, base)?;
    let engine = Engine::ephemeral(cfg.clone(), policy);
    let (mut total, mut changed, mut stricter) = (0usize, 0usize, 0usize);
    let mut cursor = since_seq;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    'pages: loop {
        let page = log
            .query(&Query { since_seq: Some(cursor), limit: 1000, ..Query::default() })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if page.is_empty() {
            break;
        }
        for rec in page {
            cursor = rec.seq;
            if limit > 0 && total >= limit {
                break 'pages;
            }
            total += 1;
            let (groups, ev) = (Vec::new(), &rec.event);
            let new = engine.evaluate(ev, &groups);
            let old = &rec.decision;
            if new.verdict == old.verdict {
                continue;
            }
            changed += 1;
            if new.verdict > old.verdict {
                stricter += 1;
            }
            let ev_json = serde_json::to_value(ev)?;
            if json_out {
                let row = json!({
                    "seq": rec.seq,
                    "agent": ev.agent,
                    "kind": ev.kind_name(),
                    "target": target(&ev_json),
                    "old": old.verdict,
                    "new": new.verdict,
                    "old_rules": rules(old),
                    "new_rules": rules(&new),
                });
                writeln!(out, "{row}")?;
            } else {
                writeln!(
                    out,
                    "#{:<6} {:<16} {:<13} {:<32} {:>6} -> {:<6} {}",
                    rec.seq,
                    ev.agent,
                    ev.kind_name(),
                    target(&ev_json),
                    old.verdict.as_str(),
                    new.verdict.as_str(),
                    rules_of(&serde_json::to_value(&new)?)
                )?;
            }
        }
    }
    eprintln!(
        "replayed {total} event(s): {changed} verdict change(s), {stricter} stricter, {} looser",
        changed - stricter
    );
    Ok(ReplaySummary { total, changed, stricter })
}

fn print_report(report: &nandi_audit::VerifyReport) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    if !report.ok {
        bail!("audit verification FAILED ({} problem(s))", report.problems.len());
    }
    eprintln!("audit chain OK: {} record(s)", report.records);
    Ok(())
}

pub fn verify_db(log: &AuditLog) -> anyhow::Result<()> {
    let report = log.verify().map_err(|e| anyhow::anyhow!("{e}"))?;
    print_report(&report)
}

pub fn verify_export(file: &Path, pubkey: &str) -> anyhow::Result<()> {
    let f = File::open(file).with_context(|| format!("opening {}", file.display()))?;
    let report = verify_jsonl(&mut BufReader::new(f), pubkey).map_err(|e| anyhow::anyhow!("{e}"))?;
    print_report(&report)
}

pub fn export(log: &AuditLog, out: &Path) -> anyhow::Result<()> {
    let n = if out == Path::new("-") {
        let stdout = std::io::stdout();
        let mut w = BufWriter::new(stdout.lock());
        let n = log.export_jsonl(&mut w).map_err(|e| anyhow::anyhow!("{e}"))?;
        w.flush()?;
        n
    } else {
        let mut w = BufWriter::new(File::create(out).with_context(|| format!("creating {}", out.display()))?);
        let n = log.export_jsonl(&mut w).map_err(|e| anyhow::anyhow!("{e}"))?;
        w.flush()?;
        n
    };
    eprintln!(
        "exported {n} record(s); verify with: nandi audit verify --export <file> --pubkey {}",
        log.public_key_hex()
    );
    Ok(())
}

/// `nandi audit trail`: administrative actions, newest first.
pub fn trail(
    log: &AuditLog,
    actor: Option<&str>,
    action: Option<&str>,
    limit: usize,
    json_out: bool,
) -> anyhow::Result<()> {
    let records =
        log.query(&Query { kind: Some("admin".into()), ..Query::default() }).map_err(|e| anyhow::anyhow!("{e}"))?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut shown = 0;
    for rec in records {
        let nandi_core::EventKind::Admin(a) = &rec.event.kind else { continue };
        if actor.is_some_and(|x| a.actor != x) || action.is_some_and(|x| !a.action.starts_with(x)) {
            continue;
        }
        if limit > 0 && shown >= limit {
            break;
        }
        shown += 1;
        if json_out {
            writeln!(
                out,
                "{}",
                json!({ "seq": rec.seq, "ts_ms": rec.event.ts_ms, "actor": a.actor, "action": a.action,
                "target": a.target, "outcome": a.outcome, "details": a.details })
            )?;
        } else {
            writeln!(
                out,
                "#{:<6} {}  {:<16} {:<22} {:<24} {}",
                rec.seq,
                crate::remote::clock_utc(rec.event.ts_ms),
                a.actor,
                a.action,
                a.target,
                a.outcome
            )?;
        }
    }
    if shown == 0 && !json_out {
        eprintln!("no administrative actions recorded");
    }
    Ok(())
}

pub fn head(log: &AuditLog) -> anyhow::Result<()> {
    let (seq, hash) = log.head();
    let records = log.len().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("{}", json!({ "seq": seq, "hash": hash, "records": records, "public_key": log.public_key_hex() }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lines_fill_defaults() {
        let (ev, groups) =
            parse_test_line(r#"{"kind":{"type":"tool_call","server":"sh","tool":"exec","args":{}}}"#).unwrap();
        assert_eq!(ev.agent, "test-agent");
        assert!(groups.is_empty());
        let (ev, groups) = parse_test_line(
            r#"{"event":{"agent":"a","kind":{"type":"tool_call","server":"sh","tool":"exec","args":{}}},"groups":["ops"]}"#,
        )
        .unwrap();
        assert_eq!((ev.agent.as_str(), groups), ("a", vec!["ops".to_string()]));
        assert!(parse_test_line("[1]").is_err());
    }

    #[test]
    fn replay_reports_changed_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("rules.yaml"),
            "rules:\n  - id: no-exec\n    match: { tool: exec }\n    action: deny\n",
        )
        .unwrap();
        let mut cfg = Config::default();
        cfg.policy.rules = vec!["rules.yaml".into()];
        let log = AuditLog::open(&dir.path().join("a.redb"), &dir.path().join("a.key")).unwrap();
        for line in [
            r#"{"kind":{"type":"tool_call","server":"sh","tool":"exec","args":{}}}"#,
            r#"{"kind":{"type":"tool_call","server":"sh","tool":"ls","args":{}}}"#,
        ] {
            let (ev, _) = parse_test_line(line).unwrap();
            log.append(&ev, &Decision::allow()).unwrap();
        }
        let s = replay(&cfg, dir.path(), &log, 0, 0, true).unwrap();
        assert_eq!(s, ReplaySummary { total: 2, changed: 1, stricter: 1 });
        let s = replay(&cfg, dir.path(), &log, 1, 0, true).unwrap();
        assert_eq!(s.total, 1);
        assert_eq!(replay(&cfg, dir.path(), &log, 0, 1, true).unwrap().total, 1);
    }
}
