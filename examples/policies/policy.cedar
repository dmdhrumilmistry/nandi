// Cedar policies, evaluated on every action next to the YAML rules.
//
// Entities nandi provides per request:
//   principal  Agent::"<agent id>", member of Group::"<group>" for each group
//   action     Action::"call_tool" | "list_tools" | "llm_request" | "a2a_send"
//   resource   Tool::"<server>/<tool>" (in Server::"<server>"),
//              Model::"<provider>/<model>", Peer::"<peer>"
//   context    { args, session: { tainted, risk (0-100), calls }, method? }
//
// Annotations: @id names the rule (reported as cedar.<id>), @message and
// @severity describe it, and @action("ask" | "alert" | "redact") on a forbid
// downgrades it from deny.
//
// With `policy.default: deny`, a tool call runs only if some permit (or YAML
// allow rule) matches it.

// Interns may never delete repositories.
@id("interns-no-repo-delete")
@message("interns may not delete repositories")
@severity("high")
forbid (
  principal in Group::"interns",
  action == Action::"call_tool",
  resource == Tool::"github/delete_repository"
);

// Merging a pull request needs a human in the loop.
@id("merge-needs-approval")
@action("ask")
forbid (
  principal,
  action == Action::"call_tool",
  resource == Tool::"github/merge_pull_request"
);

// The support group may use every tool of the CRM server.
@id("support-uses-crm")
permit (
  principal in Group::"support",
  action == Action::"call_tool",
  resource in Server::"crm"
);

// Anyone may read files under /tmp through the filesystem server.
@id("read-tmp")
permit (
  principal,
  action == Action::"call_tool",
  resource == Tool::"filesystem/read_file"
)
when { context.args has path && context.args.path like "/tmp/*" };
