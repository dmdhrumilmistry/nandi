# Research behind nandi

This page records the products and papers that shaped nandi, and which
feature each idea became. Everything nandi does in the request path is
deterministic: no LLM is consulted to allow or block a call. Optional model
based checks (the ONNX classifier) run behind a feature flag.

## Landscape

| Project | What we took | What nandi does differently |
|---|---|---|
| [Gravitee Agent Mesh](https://documentation.gravitee.io/apim/agent-mesh) | LLM, MCP and A2A proxies behind one policy chain; Cedar-like tool authorization; human approval of `tools/call` with deny on timeout; kill switch; token rate limits; shadow AI discovery | Single static binary instead of a Java platform; approvals, kill switch and budgets are local; explicit `fail_mode` instead of failing open |
| [google/agentmesh](https://github.com/google/agentmesh) | Biscuit credentials whose delegation blocks can only narrow access, down to a single MCP tool | Works over plain HTTP MCP and A2A instead of a private libp2p network |
| [agentgateway](https://github.com/agentgateway/agentgateway) | Rust data plane on hyper/tower/rustls; MCP federation; identity-filtered `tools/list`; credential injection so agents never hold upstream tokens | Adds taint tracking, value flow, behaviour models, detectors, signed audit and host sensing on top of the gateway role |
| [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) | Kill switch, trust scoring, MCP tool drift scanning | Out of process: no SDK needed in the agent |
| [AgentSight](https://github.com/eunomia-bpf/agentsight) | eBPF boundary tracing: TLS uprobes for intent, exec/file/network for effects | Correlates observed effects with the tool calls nandi saw and alerts on undeclared effects |
| [Pipelock](https://github.com/pipelab-org/pipelock) | Signed action receipts, MCP binary hash pinning, egress DLP | Hash-chained receipts in a local redb store with offline verification |
| [Falco Prempti](https://github.com/falcosecurity/prempti) | Pre-execution coding-agent hooks with allow / deny / ask | Same policy engine for hooks, MCP and LLM traffic |
| [Docker MCP Gateway](https://github.com/docker/mcp-gateway), [ToolHive](https://github.com/stacklok/toolhive) | Secret blocking in MCP payloads, per-server egress rules | No container runtime required |
| [Archestra](https://github.com/archestra-ai/archestra) | Withdraw high-privilege tools once untrusted data entered the context | Done as a boundary component for any agent framework |

## Papers and the features they became

### Least privilege for tool calls
- **Progent** ([arXiv:2504.11703](https://arxiv.org/abs/2504.11703)) and **AgentSpec** ([arXiv:2503.18666](https://arxiv.org/abs/2503.18666)): rules with argument predicates and graded actions. Became the YAML rule language (`allow`, `alert`, `redact`, `ask`, `deny`) next to Cedar.
- **MiniScope** ([arXiv:2512.11147](https://arxiv.org/abs/2512.11147)): minimal scopes per session. Became default-deny mode plus identity-filtered `tools/list`.
- **Conseca** ([arXiv:2501.17070](https://arxiv.org/abs/2501.17070)), **ACE** ([arXiv:2504.20984](https://arxiv.org/abs/2504.20984)), **IPIGuard** ([arXiv:2508.15310](https://arxiv.org/abs/2508.15310)), **DRIFT** ([arXiv:2506.12104](https://arxiv.org/abs/2506.12104)): plan first, then only allow calls that match the plan. Became plan-locked execution (`plan.mode`).

### Information flow and taint
- **CaMeL** ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813)), **FIDES** ([arXiv:2505.23643](https://arxiv.org/abs/2505.23643)), **Design Patterns for Securing LLM Agents** ([arXiv:2506.08837](https://arxiv.org/abs/2506.08837)): once untrusted data entered the context it must not trigger consequential actions. Became the sticky session taint label and the `consequential` tool class.
- **RTBAS** ([arXiv:2502.08966](https://arxiv.org/abs/2502.08966)), **AgentArmor** ([arXiv:2508.01249](https://arxiv.org/abs/2508.01249)): propagate labels only along real data dependencies. Became value-flow matching: fragments of untrusted output are fingerprinted and a later call whose arguments reuse them is escalated.
- **IsolateGPT** ([arXiv:2403.04960](https://arxiv.org/abs/2403.04960)): isolate apps from each other. Taint records which server a value came from, so cross-server flows are visible.

### Prompt injection
- **Spotlighting** ([arXiv:2403.14720](https://arxiv.org/abs/2403.14720)): delimit or datamark untrusted text. Became `taint.spotlight`.
- **MCP-Guard** ([arXiv:2508.10991](https://arxiv.org/abs/2508.10991)), **LlamaFirewall** ([arXiv:2505.03574](https://arxiv.org/abs/2505.03574)), **InjecGuard** ([arXiv:2410.22770](https://arxiv.org/abs/2410.22770)): cheap patterns first, a small classifier second. Became the pattern detector plus the optional ONNX classifier (`ml` feature).
- Benchmarks used for the evaluation harness design: **AgentDojo** ([arXiv:2406.13352](https://arxiv.org/abs/2406.13352)), **InjecAgent** ([arXiv:2403.02691](https://arxiv.org/abs/2403.02691)), **ASB** ([arXiv:2410.02644](https://arxiv.org/abs/2410.02644)), **WASP** ([arXiv:2504.18575](https://arxiv.org/abs/2504.18575)).

### MCP specific
- **ETDI** ([arXiv:2506.01333](https://arxiv.org/abs/2506.01333)) and **Securing the MCP** ([arXiv:2512.06556](https://arxiv.org/abs/2512.06556)): immutable, verifiable tool definitions. Became tool pinning: canonical JSON hash of name, description and schema; drift requires re-approval.
- **MCPTox** ([arXiv:2508.14925](https://arxiv.org/abs/2508.14925)), **Systematic Analysis of MCP Security** ([arXiv:2508.12538](https://arxiv.org/abs/2508.12538)), **MCPSecBench** ([arXiv:2508.13220](https://arxiv.org/abs/2508.13220)), **MCP Landscape** ([arXiv:2503.23278](https://arxiv.org/abs/2503.23278)): tool poisoning, shadowing and rug pulls. Became the description scanner and its eval corpus.
- **MCP Guardian** ([arXiv:2504.12757](https://arxiv.org/abs/2504.12757)): auth, rate limiting, logging and WAF-style scanning as middleware. The overall shape of the stdio wrapper.

### Runtime verification and behaviour
- **Agent-C** ([arXiv:2512.23738](https://arxiv.org/abs/2512.23738)), **AgentLTL** ([arXiv:2607.02599](https://arxiv.org/abs/2607.02599)), **VIGIL** ([arXiv:2606.26524](https://arxiv.org/abs/2606.26524)): temporal constraints on traces. Became sequence rules (`requires_prior`, `forbid_after`) evaluated incrementally.
- **Behavioral Firewall** ([arXiv:2604.26274](https://arxiv.org/abs/2604.26274)), **TraceAegis** ([arXiv:2510.11203](https://arxiv.org/abs/2510.11203)): learn benign tool sequences, flag deviations. Became the per-agent transition model with surprise scoring.
- **Pro2Guard** ([arXiv:2508.00500](https://arxiv.org/abs/2508.00500)): Markov chain over abstract states, intervene when the probability of reaching an unsafe state is high. Became the unsafe-reach lookahead in the behaviour engine.
- **ShieldAgent** ([arXiv:2503.22738](https://arxiv.org/abs/2503.22738)): only evaluate rules relevant to the invoked action. Rules are indexed by tool so evaluation cost does not grow with the rule count.

### Identity and delegation
- **Authenticated Delegation** ([arXiv:2501.09674](https://arxiv.org/abs/2501.09674)): OAuth/OIDC with delegation claims. Became JWT identity with a delegator claim.
- **AIP** ([arXiv:2603.24775](https://arxiv.org/abs/2603.24775)), **CAPMAS** ([arXiv:2609.06500](https://arxiv.org/abs/2609.06500)), **Delegation Without Trust** ([arXiv:2609.00267](https://arxiv.org/abs/2609.00267)): attenuable capability tokens verified in microseconds. Became Biscuit delegation tokens checked at the gateway.

### Multi-agent and A2A
- **A2ABreak** ([arXiv:2609.10871](https://arxiv.org/abs/2609.10871)): unprotected `contextId`s and unattested capability claims. Became `contextId` binding to the authenticated caller.
- **Agent-in-the-Middle** ([arXiv:2502.14847](https://arxiv.org/abs/2502.14847)) and **Building a Secure Agentic AI Application Leveraging A2A** ([arXiv:2504.16902](https://arxiv.org/abs/2504.16902)): card spoofing and message tampering. Became Agent Card JWS verification and card pinning.
- **Prompt Infection** ([arXiv:2410.07283](https://arxiv.org/abs/2410.07283)): injections that replicate across agents. Inbound A2A messages are untrusted for taint purposes.

### Observability and exfiltration
- **AgentSight** ([arXiv:2508.02736](https://arxiv.org/abs/2508.02736)): eBPF intent/effect correlation. Became `nandi sense`.
- **Caught in the Act(ivation)** ([arXiv:2606.04141](https://arxiv.org/abs/2606.04141)), **Whispers in the Machine** ([arXiv:2402.06922](https://arxiv.org/abs/2402.06922)): honeytokens and multi-encoding exfiltration. Became honeytokens plus base64 / hex / URL decoding before scanning.
- **AirGapAgent** ([arXiv:2405.05175](https://arxiv.org/abs/2405.05175)): contextual-integrity data minimisation. Became field-level redaction of tool output.
