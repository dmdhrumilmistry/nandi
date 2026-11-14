//! Normalized event model.
//!
//! Every capture point (HTTP proxy, stdio MCP wrapper, coding-agent hooks,
//! eBPF sensor, replay) turns what it sees into an [`Event`]. The engine only
//! ever reasons about events, so detection and policy logic is shared by all
//! capture points. Field names follow the OpenTelemetry GenAI semantic
//! conventions where one exists (`gen_ai.tool.name`, `gen_ai.usage.*`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::util::{new_id, now_ms};

/// Where an event was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// HTTP gateway in front of LLM APIs, MCP servers or A2A agents.
    Proxy,
    /// `nandi wrap` around a stdio MCP server.
    Stdio,
    /// Coding-agent hook (Claude Code, Cursor, generic).
    Hook,
    /// eBPF host sensor.
    Sensor,
    /// Re-evaluation of recorded events against a new policy.
    Replay,
    /// Evaluation harness.
    Eval,
    /// A person or tool acting through the admin API or dashboard.
    Admin,
}

/// One observed action of an agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    /// Unix epoch milliseconds.
    pub ts_ms: u64,
    pub source: Source,
    /// Authenticated agent identity, or `anonymous`.
    pub agent: String,
    /// Conversation / task scope used for taint, sequence and plan state.
    pub session: String,
    /// W3C trace id when the caller propagated one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Parent span id: nandi's span for the request, or the caller's span.
    /// The event's own span id is derived from `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub kind: EventKind,
}

impl Event {
    pub fn new(source: Source, agent: impl Into<String>, session: impl Into<String>, kind: EventKind) -> Self {
        Self {
            id: new_id(),
            ts_ms: now_ms(),
            source,
            agent: agent.into(),
            session: session.into(),
            trace_id: None,
            parent_span_id: None,
            kind,
        }
    }

    /// Short machine name of the event kind, used in metrics and logs.
    pub fn kind_name(&self) -> &'static str {
        self.kind.name()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    LlmRequest(LlmRequest),
    LlmResponse(LlmResponse),
    ToolList(ToolList),
    ToolCall(ToolCall),
    ToolResult(ToolResult),
    A2aMessage(A2aMessage),
    AgentCard(AgentCardSeen),
    PlanDeclared(PlanSpec),
    Process(ProcessEvent),
    File(FileEvent),
    Network(NetworkEvent),
    /// An administrative action: an approval, the kill switch, a policy or
    /// user change. Recorded in the same signed chain as agent events.
    Admin(AdminAction),
}

/// Who did what through the admin API.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdminAction {
    /// The authenticated user, `admin` for the admin token, `local` for
    /// loopback access without a token.
    pub actor: String,
    /// Dotted action name, e.g. `approval.approve`, `agent.kill`,
    /// `user.create`, `policy.apply`.
    pub action: String,
    /// What it acted on: an approval id, agent, user, policy document.
    pub target: String,
    /// `ok`, `denied` (not permitted) or `failed`.
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub details: Value,
}

impl EventKind {
    pub fn name(&self) -> &'static str {
        match self {
            EventKind::LlmRequest(_) => "llm_request",
            EventKind::LlmResponse(_) => "llm_response",
            EventKind::ToolList(_) => "tool_list",
            EventKind::ToolCall(_) => "tool_call",
            EventKind::ToolResult(_) => "tool_result",
            EventKind::A2aMessage(_) => "a2a_message",
            EventKind::AgentCard(_) => "agent_card",
            EventKind::PlanDeclared(_) => "plan_declared",
            EventKind::Process(_) => "process",
            EventKind::File(_) => "file",
            EventKind::Network(_) => "network",
            EventKind::Admin(_) => "admin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// A flattened chat message. Multimodal parts are reduced to their text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub text: String,
    /// For `Role::Tool`: the id of the tool call this message answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    /// For `Role::Tool`: the tool name when the provider sends it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

/// Outbound request to an LLM provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmRequest {
    /// `openai`, `anthropic`, `gemini`, ...
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub stream: bool,
    /// Names of the tools offered to the model in this request.
    #[serde(default)]
    pub tools_offered: Vec<String>,
    #[serde(default)]
    pub messages: Vec<Message>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenUsage {
    #[serde(default)]
    pub input: u64,
    #[serde(default)]
    pub output: u64,
    #[serde(default)]
    pub cached: u64,
    #[serde(default)]
    pub reasoning: u64,
}

impl TokenUsage {
    pub fn total(&self) -> u64 {
        self.input + self.output + self.reasoning
    }
}

/// A tool call requested by the model in an LLM response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCallReq {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub args: Value,
}

/// Response from an LLM provider (assembled from the stream when streaming).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmResponse {
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub usage: TokenUsage,
    #[serde(default)]
    pub tool_calls: Vec<ToolCallReq>,
    #[serde(default)]
    pub text: String,
}

/// A tool definition as advertised by an MCP server (`tools/list`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "inputSchema", alias = "input_schema")]
    pub input_schema: Value,
    /// MCP tool annotations (`readOnlyHint`, `destructiveHint`, ...). These
    /// are hints from the server and are never trusted for allow decisions.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub annotations: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolList {
    /// Logical MCP server name (route name or wrapper name).
    pub server: String,
    pub tools: Vec<ToolDef>,
}

/// A tool invocation about to be executed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub server: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default)]
    pub args: Value,
}

/// The output of a tool invocation, before the agent sees it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub server: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default)]
    pub content: Value,
    #[serde(default)]
    pub is_error: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// From the calling agent to the remote agent.
    Outbound,
    /// From the remote agent back to the caller.
    Inbound,
}

/// An A2A protocol message or task update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct A2aMessage {
    /// Remote agent (route name or card name).
    pub peer: String,
    /// JSON-RPC method, e.g. `SendMessage` or `message/send`.
    pub method: String,
    pub direction: Direction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill: Option<String>,
    #[serde(default)]
    pub text: String,
}

/// An A2A Agent Card fetched through the gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCardSeen {
    pub peer: String,
    pub url: String,
    pub name: String,
    /// SHA-256 of the canonical card (signatures excluded).
    pub digest: String,
    /// `None` when the card carries no signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_valid: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default)]
    pub skills: Vec<String>,
}

/// One step of a declared plan (plan-locked execution).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanStep {
    /// Optional step id for `after` references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Tool glob, optionally prefixed with `server/`.
    pub tool: String,
    /// Constraints on arguments, same matcher syntax as policy rules.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub args: Value,
    /// Ids of steps that must have run before this one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub after: Vec<String>,
    /// How many times the step may run (default 1, 0 = unlimited).
    #[serde(default = "one")]
    pub max_calls: u32,
}

fn one() -> u32 {
    1
}

/// A task plan declared up front by the agent or its orchestrator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanSpec {
    #[serde(default)]
    pub task: String,
    pub steps: Vec<PlanStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    #[serde(default)]
    pub uid: u32,
    pub comm: String,
    pub filename: String,
    #[serde(default)]
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEvent {
    pub pid: u32,
    pub comm: String,
    pub path: String,
    #[serde(default)]
    pub write: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub pid: u32,
    pub comm: String,
    pub daddr: String,
    pub dport: u16,
    /// Host name when known (TLS SNI or HTTP Host from the SSL uprobe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_round_trips_with_type_tag() {
        let ev = Event::new(
            Source::Stdio,
            "agent-a",
            "s1",
            EventKind::ToolCall(ToolCall {
                server: "fs".into(),
                tool: "read_file".into(),
                call_id: Some("1".into()),
                args: serde_json::json!({"path": "/etc/passwd"}),
            }),
        );
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains("\"type\":\"tool_call\""));
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
        assert_eq!(back.kind_name(), "tool_call");
    }

    #[test]
    fn plan_step_defaults_to_single_call() {
        let p: PlanSpec = serde_json::from_str(r#"{"steps":[{"tool":"search"}]}"#).unwrap();
        assert_eq!(p.steps[0].max_calls, 1);
    }
}
