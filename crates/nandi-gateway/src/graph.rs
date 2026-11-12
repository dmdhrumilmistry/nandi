//! Aggregates the audit log into the dashboard's map: who talked to what,
//! how nandi decided, and how decisions are spread over time.
//!
//! Nodes are agents, destinations (MCP servers, models, A2A peers, the host)
//! and tools; edges run from agents to destinations. Counts are kept per
//! verdict so the charts can show volume and what was flagged separately.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use nandi_audit::{AuditLog, Query};
use nandi_core::{EventKind, Verdict};

/// Records read per request at most; older ones in the window are skipped.
const MAX_RECORDS: usize = 50_000;
/// Destinations and tools shown at most; the rest fold into "other".
const MAX_DESTINATIONS: usize = 40;
const MAX_TOOLS: usize = 80;

#[derive(Debug, Default, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Counts {
    #[serde(skip_serializing_if = "is_zero")]
    pub allow: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub alert: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub redact: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub ask: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub deny: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl Counts {
    fn add(&mut self, v: Verdict) {
        match v {
            Verdict::Allow => self.allow += 1,
            Verdict::Alert => self.alert += 1,
            Verdict::Redact => self.redact += 1,
            Verdict::Ask => self.ask += 1,
            Verdict::Deny => self.deny += 1,
        }
    }

    fn merge(&mut self, o: &Counts) {
        self.allow += o.allow;
        self.alert += o.alert;
        self.redact += o.redact;
        self.ask += o.ask;
        self.deny += o.deny;
    }

    pub fn total(&self) -> u64 {
        self.allow + self.alert + self.redact + self.ask + self.deny
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub id: String,
    pub kind: &'static str,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub counts: Counts,
}

#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    pub source: String,
    pub target: String,
    pub counts: Counts,
}

#[derive(Debug, Clone, Serialize)]
pub struct Bucket {
    /// Start of the bucket, Unix milliseconds.
    pub t: u64,
    #[serde(flatten)]
    pub counts: Counts,
}

#[derive(Debug, Clone, Serialize)]
pub struct Timeline {
    pub bucket_secs: u64,
    pub buckets: Vec<Bucket>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Graph {
    pub window_secs: u64,
    pub generated_ms: u64,
    /// True when the window held more records than were read.
    pub truncated: bool,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub timeline: Timeline,
}

/// Where an event went: (kind, destination name, tool).
fn destination(kind: &EventKind) -> (&'static str, String, Option<String>) {
    match kind {
        EventKind::ToolCall(c) => ("server", c.server.clone(), Some(c.tool.clone())),
        EventKind::ToolResult(r) => ("server", r.server.clone(), Some(r.tool.clone())),
        EventKind::ToolList(l) => ("server", l.server.clone(), None),
        EventKind::LlmRequest(r) => ("model", format!("{}/{}", r.provider, r.model), None),
        EventKind::LlmResponse(r) => ("model", format!("{}/{}", r.provider, r.model), None),
        EventKind::A2aMessage(m) => ("peer", m.peer.clone(), None),
        EventKind::AgentCard(c) => ("peer", c.peer.clone(), None),
        EventKind::PlanDeclared(_) => ("plan", "plan".into(), None),
        EventKind::Process(_) | EventKind::File(_) | EventKind::Network(_) => ("host", "host".into(), None),
    }
}

/// Build the graph for the last `window_secs`, with `buckets` timeline buckets.
pub fn build(log: &AuditLog, now_ms: u64, window_secs: u64, buckets: usize) -> nandi_core::Result<Graph> {
    let window_secs = window_secs.clamp(60, 7 * 86_400);
    let buckets = buckets.clamp(6, 240);
    let start = now_ms.saturating_sub(window_secs * 1000);
    let q = Query { since_ts_ms: Some(start), limit: MAX_RECORDS + 1, ..Query::default() };
    let mut records = log.query(&q)?;
    let truncated = records.len() > MAX_RECORDS;
    records.truncate(MAX_RECORDS);

    let bucket_ms = (window_secs * 1000).div_ceil(buckets as u64).max(1000);
    let mut timeline = vec![Counts::default(); buckets];
    let mut agents: BTreeMap<String, Counts> = BTreeMap::new();
    let mut dests: HashMap<(String, &'static str), Counts> = HashMap::new();
    let mut tools: HashMap<(String, String), Counts> = HashMap::new();
    let mut edges: HashMap<(String, String), Counts> = HashMap::new();

    for r in &records {
        let (ev, v) = (&r.event, r.decision.verdict);
        if ev.ts_ms < start {
            continue;
        }
        let i = (((ev.ts_ms - start) / bucket_ms) as usize).min(buckets - 1);
        timeline[i].add(v);
        let agent_id = format!("agent:{}", ev.agent);
        agents.entry(ev.agent.clone()).or_default().add(v);
        let (kind, dest, tool) = destination(&ev.kind);
        let dest_id = format!("{kind}:{dest}");
        dests.entry((dest.clone(), kind)).or_default().add(v);
        edges.entry((agent_id, dest_id.clone())).or_default().add(v);
        if let Some(t) = tool {
            tools.entry((dest_id, t)).or_default().add(v);
        }
    }

    // Keep the busiest destinations and tools; fold the rest.
    let mut dest_list: Vec<((String, &'static str), Counts)> = dests.into_iter().collect();
    dest_list.sort_by(|a, b| b.1.total().cmp(&a.1.total()).then(a.0.0.cmp(&b.0.0)));
    let mut nodes: Vec<Node> = agents
        .into_iter()
        .map(|(a, counts)| Node { id: format!("agent:{a}"), kind: "agent", label: a, parent: None, counts })
        .collect();
    let mut keep_dest: HashMap<String, String> = HashMap::new();
    let mut other = Counts::default();
    for (i, ((name, kind), counts)) in dest_list.into_iter().enumerate() {
        let id = format!("{kind}:{name}");
        if i < MAX_DESTINATIONS {
            keep_dest.insert(id.clone(), id.clone());
            nodes.push(Node { id, kind, label: name, parent: None, counts });
        } else {
            keep_dest.insert(id, "other:other".into());
            other.merge(&counts);
        }
    }
    if other.total() > 0 {
        nodes.push(Node {
            id: "other:other".into(),
            kind: "other",
            label: "other".into(),
            parent: None,
            counts: other,
        });
    }
    let mut tool_list: Vec<((String, String), Counts)> =
        tools.into_iter().filter(|((d, _), _)| keep_dest.get(d).is_some_and(|k| k == d)).collect();
    tool_list.sort_by(|a, b| b.1.total().cmp(&a.1.total()).then(a.0.cmp(&b.0)));
    for ((dest_id, tool), counts) in tool_list.into_iter().take(MAX_TOOLS) {
        let server = dest_id.split_once(':').map(|(_, s)| s).unwrap_or(&dest_id).to_string();
        nodes.push(Node {
            id: format!("tool:{server}/{tool}"),
            kind: "tool",
            label: tool,
            parent: Some(dest_id),
            counts,
        });
    }
    let mut merged: HashMap<(String, String), Counts> = HashMap::new();
    for ((src, dst), c) in edges {
        let dst = keep_dest.get(&dst).cloned().unwrap_or(dst);
        merged.entry((src, dst)).or_default().merge(&c);
    }
    let mut edges: Vec<Edge> =
        merged.into_iter().map(|((source, target), counts)| Edge { source, target, counts }).collect();
    edges.sort_by(|a, b| b.counts.total().cmp(&a.counts.total()).then(a.source.cmp(&b.source)));

    Ok(Graph {
        window_secs,
        generated_ms: now_ms,
        truncated,
        nodes,
        edges,
        timeline: Timeline {
            bucket_secs: bucket_ms / 1000,
            buckets: timeline
                .into_iter()
                .enumerate()
                .map(|(i, counts)| Bucket { t: start + i as u64 * bucket_ms, counts })
                .collect(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::{Category, Decision, Event, Finding, Severity, Source, ToolCall};

    fn call(agent: &str, server: &str, tool: &str, ts: u64) -> Event {
        let mut ev = Event::new(
            Source::Eval,
            agent,
            "s",
            EventKind::ToolCall(ToolCall {
                server: server.into(),
                tool: tool.into(),
                call_id: None,
                args: serde_json::json!({}),
            }),
        );
        ev.ts_ms = ts;
        ev
    }

    #[test]
    fn aggregates_edges_tools_and_timeline() {
        let log = AuditLog::open_in_memory().unwrap();
        let now = 10_000_000;
        let mut deny = Decision::allow();
        deny.push(Finding::new("r", Category::Policy, Severity::High, Verdict::Deny, "no"));
        log.append(&call("a", "github", "create_issue", now - 50_000), &Decision::allow()).unwrap();
        log.append(&call("a", "github", "create_issue", now - 40_000), &Decision::allow()).unwrap();
        log.append(&call("a", "github", "delete_repo", now - 30_000), &deny).unwrap();
        log.append(&call("b", "slack", "post", now - 5_000), &Decision::allow()).unwrap();
        // Outside the window.
        log.append(&call("c", "old", "x", now - 900_000), &Decision::allow()).unwrap();

        let g = build(&log, now, 120, 12).unwrap();
        assert!(!g.truncated);
        let ids: Vec<&str> = g.nodes.iter().map(|n| n.id.as_str()).collect();
        assert!(ids.contains(&"agent:a") && ids.contains(&"server:github") && ids.contains(&"tool:github/delete_repo"));
        assert!(!ids.iter().any(|i| i.contains("old")));
        let e = g.edges.iter().find(|e| e.source == "agent:a" && e.target == "server:github").unwrap();
        assert_eq!((e.counts.allow, e.counts.deny), (2, 1));
        assert_eq!(g.timeline.buckets.len(), 12);
        assert_eq!(g.timeline.buckets.iter().map(|b| b.counts.total()).sum::<u64>(), 4);
        let json = serde_json::to_value(&g).unwrap();
        assert_eq!(json["edges"][0]["counts"]["allow"], 2);
        assert!(json["timeline"]["buckets"][0].get("allow").is_none() || json["timeline"]["buckets"][0]["t"].is_u64());
    }
}
