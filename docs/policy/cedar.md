# Cedar policies

[Cedar](https://www.cedarpolicy.com) is a policy language from AWS with a
clear permit and forbid model that can be analysed formally. nandi evaluates
the files listed under `policy.cedar` on every action, next to the
[YAML rules](rules.md). Use Cedar for who-may-do-what across agents and
groups; use YAML rules for argument checks and sequences.

## What nandi provides

| | Value |
|---|---|
| principal | `Agent::"<agent id>"`, a member of `Group::"<group>"` for each of its groups |
| action | `Action::"call_tool"`, `"list_tools"`, `"llm_request"` or `"a2a_send"` |
| resource | `Tool::"<server>/<tool>"` (in `Server::"<server>"`, attributes `name`, `server` and `capabilities`, a set such as `["payment"]`; see [capabilities](capabilities.md)), `Model::"<provider>/<model>"`, `Peer::"<peer>"` |
| context | `args` (the call's arguments), `session` (`tainted`, `risk` from 0 to 100, `calls`), `method` for A2A |

Arguments are made Cedar-safe: floats become strings, nulls are dropped,
deep nesting is cut off and keys starting with `__` are removed. Policies that
read an argument should check it exists first
(`context.args has path && ...`).

Your own entities (for example a group hierarchy) can be loaded from a Cedar
JSON entities file with `policy.cedar_entities`.

## Examples

```cedar
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
forbid (principal, action == Action::"call_tool", resource == Tool::"github/merge_pull_request");

// The support group may use every tool of the CRM server.
@id("support-uses-crm")
permit (principal in Group::"support", action == Action::"call_tool", resource in Server::"crm");

// Anyone may read files under /tmp through the filesystem server.
@id("read-tmp")
permit (principal, action == Action::"call_tool", resource == Tool::"filesystem/read_file")
when { context.args has path && context.args.path like "/tmp/*" };
```

## Annotations

| Annotation | Effect |
|---|---|
| `@id("...")` | names the finding (`cedar.<id>`); otherwise `cedar.policy0` and so on |
| `@message("...")` | the finding's message |
| `@severity("...")` | `info`, `low`, `medium` (default), `high` or `critical` |
| `@action("ask" \| "alert" \| "redact")` | on a `forbid`, hold or flag instead of deny |

## How results combine

- A matching `forbid` is a finding with its verdict (deny unless `@action`
  says otherwise).
- A matching `permit` counts as an explicit allow for `policy.default: deny`.
- No match is neither: the call proceeds unless default deny is on, in which
  case it gets `policy.default-deny`.
- Evaluation errors (usually a missing attribute) become a single low
  `cedar.error` alert rather than a crash or a silent pass.

The `ip`, `decimal` and `datetime` Cedar extensions are not compiled in.
