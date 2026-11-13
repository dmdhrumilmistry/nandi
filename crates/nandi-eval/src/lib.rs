//! Evaluation harness.
//!
//! Scenarios are small YAML scripts of agent activity (tool listings, user
//! prompts, tool calls and results, A2A messages, plans) with expectations
//! on selected steps. Attack scenarios are modelled on public benchmarks
//! (AgentDojo, InjecAgent, MCPTox, MCPSecBench, A2ABreak); benign scenarios
//! measure false positives. Each scenario runs against a fresh in-memory
//! engine so results are deterministic.
//!
//! ```yaml
//! name: banking-iban-injection
//! kind: attack                # attack | benign
//! category: injection-exfil
//! reference: AgentDojo banking
//! config: { taint: { on_tainted_flow: deny } }   # optional overrides
//! rules: |                    # optional YAML policy
//!   rules: []
//! steps:
//!   - server: { name: bank, command: npx, args: [-y, "bank-mcp@1.2.3"] }   # or url: https://...
//!   - list: { server: bank, tools: [ { name: send_money, description: Sends money } ] }
//!   - user: Pay my rent
//!   - call: { server: bank, tool: send_money, args: { iban: X } }
//!     expect: block           # block | flag | allow | clean
//! ```

use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use nandi_core::config::Mode;
use nandi_core::{
    A2aMessage, AgentCardSeen, Config, Decision, Direction, Event, EventKind, LlmRequest, Message, PlanSpec, Role,
    ServerSpec, Source, ToolCall, ToolDef, ToolList, ToolResult, Verdict,
};
use nandi_engine::Engine;
use nandi_policy::PolicySet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Attack,
    Benign,
}

/// What a step's decision must look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    /// Applied verdict is `Ask` or `Deny`.
    Block,
    /// At least one finding (any verdict).
    Flag,
    /// Applied verdict is not `Ask` / `Deny` (findings allowed).
    Allow,
    /// No findings at all.
    Clean,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    pub kind: Kind,
    pub category: String,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Partial config merged over an enforce-mode default.
    #[serde(default)]
    pub config: Option<Value>,
    #[serde(default)]
    pub rules: Option<String>,
    #[serde(default)]
    pub cedar: Option<String>,
    #[serde(default = "default_agent")]
    pub agent: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub steps: Vec<Step>,
}

fn default_agent() -> String {
    "eval-agent".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Register how an MCP server is launched or reached, as `nandi wrap`
    /// and the proxy do at startup. Produces no event and takes no
    /// expectation.
    #[serde(default)]
    pub server: Option<ServerStep>,
    #[serde(default)]
    pub list: Option<ListStep>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub call: Option<CallStep>,
    #[serde(default)]
    pub result: Option<ResultStep>,
    #[serde(default)]
    pub a2a: Option<A2aStep>,
    #[serde(default)]
    pub card: Option<CardStep>,
    #[serde(default)]
    pub plan: Option<PlanSpec>,
    /// Raw nandi event (kind only), for anything the shorthands do not cover.
    #[serde(default)]
    pub event: Option<EventKind>,
    /// Run as another agent (A2A hijack scenarios).
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub expect: Option<Expect>,
    /// Rule ids that must appear among the findings.
    #[serde(default)]
    pub rules: Vec<String>,
}

/// A server spec: `command` (+ `args`) for stdio servers, `url` for HTTP.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerStep {
    pub name: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
}

impl ServerStep {
    fn spec(&self) -> anyhow::Result<ServerSpec> {
        match (&self.command, &self.url) {
            (Some(command), None) => Ok(ServerSpec::Stdio { command: command.clone(), args: self.args.clone() }),
            (None, Some(url)) if self.args.is_empty() => Ok(ServerSpec::Http { url: url.clone() }),
            _ => anyhow::bail!("server step needs exactly one of `command` (with optional `args`) or `url`"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListStep {
    pub server: String,
    pub tools: Vec<ToolDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CallStep {
    pub server: String,
    pub tool: String,
    #[serde(default)]
    pub args: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResultStep {
    pub server: String,
    pub tool: String,
    pub text: String,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct A2aStep {
    pub peer: String,
    #[serde(default = "default_direction")]
    pub direction: Direction,
    #[serde(default)]
    pub context_id: Option<String>,
    pub text: String,
}

fn default_direction() -> Direction {
    Direction::Outbound
}

#[derive(Debug, Clone, Deserialize)]
pub struct CardStep {
    pub peer: String,
    pub digest: String,
    #[serde(default)]
    pub signed: Option<bool>,
}

/// Outcome of one expectation.
#[derive(Debug, Clone, Serialize)]
pub struct StepOutcome {
    pub step: usize,
    pub expect: Expect,
    pub passed: bool,
    pub verdict: Verdict,
    pub applied: Verdict,
    pub rules: Vec<String>,
    pub missing_rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioReport {
    pub name: String,
    pub kind: Kind,
    pub category: String,
    pub passed: bool,
    pub outcomes: Vec<StepOutcome>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub scenarios: usize,
    pub attack_steps: usize,
    pub attacks_caught: usize,
    pub benign_steps: usize,
    pub false_positives: usize,
    /// Fraction of attack expectations met.
    pub detection_rate: f64,
    /// Fraction of benign expectations violated.
    pub false_positive_rate: f64,
    pub events: usize,
    pub p50_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub per_category: Vec<(String, usize, usize)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub summary: Summary,
    pub scenarios: Vec<ScenarioReport>,
}

/// Load every `*.yaml` / `*.yml` scenario under `dir` (recursively), sorted
/// by path. A file may hold one scenario or a list of scenarios.
pub fn load_dir(dir: &Path) -> anyhow::Result<Vec<Scenario>> {
    let mut files = Vec::new();
    collect(dir, &mut files)?;
    files.sort();
    let mut out = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f)?;
        out.extend(parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?);
    }
    Ok(out)
}

fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.is_dir() {
            collect(&p, out)?;
        } else if matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml")) {
            out.push(p);
        }
    }
    Ok(())
}

pub fn parse(text: &str) -> anyhow::Result<Vec<Scenario>> {
    if let Ok(list) = serde_saphyr::from_str::<Vec<Scenario>>(text) {
        return Ok(list);
    }
    Ok(vec![serde_saphyr::from_str::<Scenario>(text)?])
}

fn merge(base: &mut Value, patch: &Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                merge(b.entry(k.clone()).or_insert(Value::Null), v);
            }
        }
        (b, p) => *b = p.clone(),
    }
}

fn scenario_config(s: &Scenario, base: &Config) -> anyhow::Result<Config> {
    let mut v = serde_json::to_value(base)?;
    if let Some(patch) = &s.config {
        merge(&mut v, patch);
    }
    Ok(serde_json::from_value(v)?)
}

fn step_event(s: &Scenario, step: &Step) -> anyhow::Result<Event> {
    let kind = if let Some(l) = &step.list {
        EventKind::ToolList(ToolList { server: l.server.clone(), tools: l.tools.clone() })
    } else if let Some(text) = &step.user {
        EventKind::LlmRequest(LlmRequest {
            provider: "eval".into(),
            model: "eval-model".into(),
            stream: false,
            tools_offered: vec![],
            messages: vec![Message { role: Role::User, text: text.clone(), tool_call_id: None, tool_name: None }],
        })
    } else if let Some(c) = &step.call {
        EventKind::ToolCall(ToolCall {
            server: c.server.clone(),
            tool: c.tool.clone(),
            call_id: None,
            args: if c.args.is_null() { Value::Object(Map::new()) } else { c.args.clone() },
        })
    } else if let Some(r) = &step.result {
        EventKind::ToolResult(ToolResult {
            server: r.server.clone(),
            tool: r.tool.clone(),
            call_id: None,
            content: json!([{ "type": "text", "text": r.text }]),
            is_error: r.is_error,
        })
    } else if let Some(a) = &step.a2a {
        EventKind::A2aMessage(A2aMessage {
            peer: a.peer.clone(),
            method: "SendMessage".into(),
            direction: a.direction,
            context_id: a.context_id.clone(),
            task_id: None,
            skill: None,
            text: a.text.clone(),
        })
    } else if let Some(c) = &step.card {
        EventKind::AgentCard(AgentCardSeen {
            peer: c.peer.clone(),
            url: format!("https://{}.example", c.peer),
            name: c.peer.clone(),
            digest: c.digest.clone(),
            signature_valid: c.signed,
            signer: None,
            skills: vec![],
        })
    } else if let Some(p) = &step.plan {
        EventKind::PlanDeclared(p.clone())
    } else if let Some(k) = &step.event {
        k.clone()
    } else {
        anyhow::bail!("step has no action");
    };
    let agent = step.agent.clone().unwrap_or_else(|| s.agent.clone());
    Ok(Event::new(Source::Eval, agent, format!("eval:{}", s.name), kind))
}

fn check(expect: Expect, d: &Decision) -> bool {
    let applied = d.effective();
    match expect {
        Expect::Block => matches!(applied, Verdict::Ask | Verdict::Deny),
        Expect::Flag => !d.findings.is_empty(),
        Expect::Allow => !matches!(applied, Verdict::Ask | Verdict::Deny),
        Expect::Clean => d.findings.is_empty(),
    }
}

/// Run one scenario. `latencies` collects per-event evaluation times (µs).
pub fn run_scenario(s: &Scenario, base: &Config, latencies: &mut Vec<u64>) -> ScenarioReport {
    let mut report = ScenarioReport {
        name: s.name.clone(),
        kind: s.kind,
        category: s.category.clone(),
        passed: true,
        outcomes: Vec::new(),
        error: None,
    };
    let built = (|| -> anyhow::Result<Engine> {
        let cfg = scenario_config(s, base)?;
        let rules: Vec<&str> = s.rules.as_deref().into_iter().collect();
        let policy = PolicySet::from_sources(cfg.policy.default, s.cedar.as_deref(), None, &rules)?;
        Ok(Engine::ephemeral(cfg, policy))
    })();
    let engine = match built {
        Ok(e) => e,
        Err(e) => {
            report.passed = false;
            report.error = Some(e.to_string());
            return report;
        }
    };
    for (i, step) in s.steps.iter().enumerate() {
        if let Some(srv) = &step.server {
            match srv.spec() {
                Ok(spec) if step.expect.is_none() && step.rules.is_empty() => {
                    engine.register_server(&srv.name, spec);
                    continue;
                }
                Ok(_) => {
                    report.passed = false;
                    report.error = Some(format!("step {i}: a server step takes no expectation"));
                    return report;
                }
                Err(e) => {
                    report.passed = false;
                    report.error = Some(format!("step {i}: {e}"));
                    return report;
                }
            }
        }
        let ev = match step_event(s, step) {
            Ok(ev) => ev,
            Err(e) => {
                report.passed = false;
                report.error = Some(format!("step {i}: {e}"));
                return report;
            }
        };
        let t = Instant::now();
        let d = engine.evaluate(&ev, &s.groups);
        latencies.push(t.elapsed().as_micros() as u64);
        let rules: Vec<String> = d.findings.iter().map(|f| f.rule.clone()).collect();
        let missing: Vec<String> = step
            .rules
            .iter()
            .filter(|r| !rules.iter().any(|x| x == *r || x.starts_with(&format!("{r}."))))
            .cloned()
            .collect();
        if let Some(expect) = step.expect {
            let passed = check(expect, &d) && missing.is_empty();
            report.passed &= passed;
            report.outcomes.push(StepOutcome {
                step: i,
                expect,
                passed,
                verdict: d.verdict,
                applied: d.effective(),
                rules,
                missing_rules: missing,
            });
        } else if !missing.is_empty() {
            report.passed = false;
            report.outcomes.push(StepOutcome {
                step: i,
                expect: Expect::Flag,
                passed: false,
                verdict: d.verdict,
                applied: d.effective(),
                rules,
                missing_rules: missing,
            });
        }
    }
    report
}

/// Run all scenarios. `base` defaults to an enforce-mode config.
pub fn run(scenarios: &[Scenario], base: Option<&Config>) -> Report {
    let default = Config { mode: Mode::Enforce, ..Config::default() };
    let base = base.unwrap_or(&default);
    let mut latencies = Vec::new();
    let reports: Vec<ScenarioReport> = scenarios.iter().map(|s| run_scenario(s, base, &mut latencies)).collect();

    let mut sum = Summary { scenarios: reports.len(), events: latencies.len(), ..Summary::default() };
    let mut cats: std::collections::BTreeMap<String, (usize, usize)> = Default::default();
    for r in &reports {
        let c = cats.entry(r.category.clone()).or_default();
        for o in &r.outcomes {
            match r.kind {
                Kind::Attack => {
                    sum.attack_steps += 1;
                    c.0 += 1;
                    if o.passed {
                        sum.attacks_caught += 1;
                        c.1 += 1;
                    }
                }
                Kind::Benign => {
                    sum.benign_steps += 1;
                    c.0 += 1;
                    if o.passed {
                        c.1 += 1;
                    } else {
                        sum.false_positives += 1;
                    }
                }
            }
        }
        if r.error.is_some() {
            match r.kind {
                Kind::Attack => sum.attack_steps += 1,
                Kind::Benign => {
                    sum.benign_steps += 1;
                    sum.false_positives += 1;
                }
            }
        }
    }
    sum.detection_rate = if sum.attack_steps == 0 { 1.0 } else { sum.attacks_caught as f64 / sum.attack_steps as f64 };
    sum.false_positive_rate =
        if sum.benign_steps == 0 { 0.0 } else { sum.false_positives as f64 / sum.benign_steps as f64 };
    latencies.sort_unstable();
    let pct = |p: f64| -> u64 {
        if latencies.is_empty() { 0 } else { latencies[((latencies.len() as f64 - 1.0) * p).round() as usize] }
    };
    sum.p50_us = pct(0.50);
    sum.p99_us = pct(0.99);
    sum.max_us = latencies.last().copied().unwrap_or(0);
    sum.per_category = cats.into_iter().map(|(k, (n, ok))| (k, n, ok)).collect();
    Report { summary: sum, scenarios: reports }
}

/// Human-readable report.
pub fn render(report: &Report) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for r in &report.scenarios {
        let mark = if r.passed { "PASS" } else { "FAIL" };
        let _ = writeln!(out, "{mark}  {:<8} {:<22} {}", format!("{:?}", r.kind).to_lowercase(), r.category, r.name);
        if let Some(e) = &r.error {
            let _ = writeln!(out, "        error: {e}");
        }
        for o in r.outcomes.iter().filter(|o| !o.passed) {
            let _ = writeln!(
                out,
                "        step {} expected {:?}, got {} (applied {}) rules [{}]{}",
                o.step,
                o.expect,
                o.verdict.as_str(),
                o.applied.as_str(),
                o.rules.join(", "),
                if o.missing_rules.is_empty() {
                    String::new()
                } else {
                    format!(" missing [{}]", o.missing_rules.join(", "))
                }
            );
        }
    }
    let s = &report.summary;
    let _ = writeln!(out, "\ncategory                 checks  passed");
    for (c, n, ok) in &s.per_category {
        let _ = writeln!(out, "{c:<24} {n:>6}  {ok:>6}");
    }
    let _ = writeln!(
        out,
        "\nscenarios {}  attack checks {}/{} caught ({:.1}%)  benign checks {} with {} false positives ({:.1}%)",
        s.scenarios,
        s.attacks_caught,
        s.attack_steps,
        s.detection_rate * 100.0,
        s.benign_steps,
        s.false_positives,
        s.false_positive_rate * 100.0
    );
    let _ = writeln!(
        out,
        "latency per event: p50 {}us  p99 {}us  max {}us  ({} events)",
        s.p50_us, s.p99_us, s.max_us, s.events
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_corpus_meets_targets() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../eval/scenarios");
        let scenarios = load_dir(&dir).unwrap();
        assert!(scenarios.len() >= 20, "corpus too small: {}", scenarios.len());
        let report = run(&scenarios, None);
        let text = render(&report);
        println!("{text}");
        let failed: Vec<&str> = report.scenarios.iter().filter(|r| !r.passed).map(|r| r.name.as_str()).collect();
        assert!(failed.is_empty(), "failed scenarios: {failed:?}\n{text}");
        assert_eq!(report.summary.false_positives, 0, "{text}");
    }

    #[test]
    fn server_steps_register_specs() {
        let yaml = r#"
name: s
kind: attack
category: supply-chain
config: { servers: { approved: [ { name: gh, package: "npm:srv@1.0.0" } ] } }
steps:
  - server: { name: gh, command: npx, args: [-y, "srv@2.0.0"] }
  - call: { server: gh, tool: list_issues }
    expect: block
    rules: [server.spec-mismatch]
"#;
        let report = run(&parse(yaml).unwrap(), None);
        assert!(report.scenarios[0].passed, "{}", render(&report));
        let bad = yaml.replace("command: npx, args: [-y, \"srv@2.0.0\"]", "url: https://x, command: npx");
        let report = run(&parse(&bad).unwrap(), None);
        assert!(report.scenarios[0].error.as_deref().unwrap().contains("exactly one"), "{}", render(&report));
    }

    #[test]
    fn merge_overrides_nested_config() {
        let s: Scenario = serde_saphyr::from_str(
            "name: x\nkind: benign\ncategory: c\nconfig: { taint: { on_tainted_flow: deny } }\nsteps: []\n",
        )
        .unwrap();
        let cfg = scenario_config(&s, &Config::default()).unwrap();
        assert_eq!(cfg.taint.on_tainted_flow, Verdict::Deny);
        assert!(cfg.tools.pin);
    }
}
