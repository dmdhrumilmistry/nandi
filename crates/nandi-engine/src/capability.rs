//! Deterministic capability classification of tools.
//!
//! [`classify`] infers what a tool can do from its definition, and
//! [`classify_name`] from a bare `server/tool` name (tools seen only through
//! coding-agent hooks or requested by a model as local tools). Nothing here
//! produces findings: capabilities are inputs to policy rules
//! (`match.capability`, Cedar `resource.capabilities`) and to risk scores.
//!
//! # How a tool is classified
//!
//! 1. The name is split into lowercase tokens at `_`, `-`, `.`, `/`, spaces
//!    and camelCase boundaries, and plurals are folded (`listUsers` becomes
//!    `list`, `user`).
//! 2. Every token is looked up in the verb dictionaries ([`VERBS`]). The
//!    first verb is the *primary* verb: when it reads (`get`, `list`,
//!    `search`, ...) the nouns after it are objects being read, so
//!    `list_payments` is read-only while `create_payment` moves money.
//! 3. Nouns refine the verbs ([`NOUNS`]): a delete or write on a file noun
//!    (`file`, `dir`, `path`) is `file_delete` / `file_write`, otherwise
//!    `data_deletion` / `data_modification`; writes on payment nouns are
//!    `payment`, on identity nouns `identity_admin`, on message nouns
//!    `external_send`. Secret nouns (`secret`, `token`, `password`, `api key`)
//!    mean `credential_access` whatever the verb.
//! 4. Top-level input schema properties add evidence ([`PARAMS`]): `command`
//!    or `script` means command execution, `sql` / `query` together with a
//!    write or execute verb means arbitrary SQL, `amount` with `iban` or
//!    `account` means a payment, a recipient with a body means sending, a URL
//!    means fetching, a `path` puts writes and deletes in the file context.
//! 5. When the name and schema say nothing, a few unambiguous phrases in the
//!    description are used ([`DESCRIPTION_PHRASES`]).
//! 6. MCP annotations come last. `readOnlyHint: true` reduces the result to
//!    `read_only` unless the name implies a capability of weight 20 or more
//!    (deleting, sending, paying, running commands, secrets, identity); the
//!    contradiction is kept as a note, never a finding. `destructiveHint:
//!    true` adds `data_deletion` when nothing else was inferred and
//!    `openWorldHint: true` adds `network_fetch`.
//! 7. A tool that only reads gets `read_only`; a tool nothing is known about
//!    gets no capabilities.
//!
//! Built-in tools of coding agents on the `local` server are mapped
//! explicitly ([`LOCAL_TOOLS`]): `Bash` runs commands, `Write` / `Edit`
//! write files, `WebFetch` fetches, `Read` / `Grep` read, `Task` has none.

use serde_json::Value;

use nandi_core::{Capability, ToolDef};

use crate::engine::LOCAL_SERVER;

/// Verb classes found in tool names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    /// Reads without side effects.
    Read,
    /// Fetches or searches remote content.
    Fetch,
    /// Creates or changes something.
    Write,
    /// Deletes something.
    Delete,
    /// Runs commands or code.
    Exec,
    /// Sends something outside.
    Send,
    /// Moves money.
    Pay,
    /// Grants or revokes access.
    Grant,
}

/// Verb dictionaries: token -> verb class. Tokens are lowercase and
/// singular.
const VERBS: &[(Verb, &[&str])] = &[
    (
        Verb::Read,
        &[
            "get",
            "list",
            "read",
            "find",
            "query",
            "describe",
            "show",
            "view",
            "lookup",
            "retrieve",
            "check",
            "count",
            "inspect",
            "stat",
            "info",
            "cat",
            "ls",
            "grep",
            "glob",
            "diff",
            "log",
            "summarize",
            "analyze",
            "explain",
            "preview",
            "export",
            "head",
            "tail",
            "load",
            "open",
            "watch",
            "poll",
            "resolve",
            "whoami",
            "status",
        ],
    ),
    (
        Verb::Fetch,
        &[
            "fetch",
            "browse",
            "browser",
            "http",
            "https",
            "url",
            "download",
            "search",
            "crawl",
            "scrape",
            "navigate",
            "curl",
            "wget",
            "web",
            "webpage",
            "website",
            "goto",
            "snapshot",
            "screenshot",
        ],
    ),
    (
        Verb::Write,
        &[
            "write",
            "create",
            "update",
            "edit",
            "insert",
            "upsert",
            "set",
            "put",
            "add",
            "modify",
            "patch",
            "save",
            "rename",
            "move",
            "mv",
            "copy",
            "cp",
            "append",
            "replace",
            "merge",
            "commit",
            "push",
            "apply",
            "change",
            "assign",
            "close",
            "reopen",
            "lock",
            "unlock",
            "label",
            "fork",
            "install",
            "deploy",
            "enable",
            "disable",
            "configure",
            "mkdir",
            "touch",
            "import",
            "restore",
            "approve",
            "reject",
            "submit",
            "schedule",
            "mark",
            "star",
            "archive",
            "click",
            "type",
            "fill",
            "press",
            "select",
            "drag",
            "hover",
            "draft",
            "new",
            "make",
            "store",
            "record",
            "transfer",
            "cancel",
            "complete",
            "resolve_thread",
            "trigger",
            "start",
            "stop",
            "restart",
            "scale",
            "rollback",
            "upgrade",
        ],
    ),
    (
        Verb::Delete,
        &[
            "delete",
            "del",
            "remove",
            "rm",
            "rmdir",
            "drop",
            "purge",
            "truncate",
            "destroy",
            "erase",
            "wipe",
            "unlink",
            "trash",
            "void",
            "uninstall",
            "terminate",
        ],
    ),
    (
        Verb::Exec,
        &[
            "exec",
            "execute",
            "run",
            "shell",
            "bash",
            "sh",
            "zsh",
            "powershell",
            "pwsh",
            "cmd",
            "command",
            "eval",
            "evaluate",
            "spawn",
            "terminal",
            "subprocess",
            "script",
            "repl",
            "interpret",
        ],
    ),
    (
        Verb::Send,
        &[
            "send",
            "post",
            "publish",
            "email",
            "mail",
            "message",
            "notify",
            "tweet",
            "reply",
            "broadcast",
            "forward",
            "dm",
            "sms",
            "webhook",
            "share",
            "announce",
            "upload",
            "invite",
            "text_message",
            "chat_postmessage",
        ],
    ),
    (
        Verb::Pay,
        &["pay", "refund", "charge", "wire", "payout", "withdraw", "purchase", "buy", "remit", "transfer_fund"],
    ),
    (Verb::Grant, &["grant", "revoke", "invite", "impersonate", "promote", "demote", "authorize", "deauthorize"]),
];

/// Noun classes that refine verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Noun {
    /// Files and directories: writes and deletes are file operations.
    File,
    /// Money: writes move money.
    Payment,
    /// Users, roles and permissions: writes administer identity.
    Identity,
    /// Messages, emails, posts: creating one sends it.
    Message,
    /// Secrets of any kind: touching them is credential access.
    Secret,
    /// SQL: executing it changes and deletes data rather than running
    /// commands on the host.
    Sql,
}

/// Noun dictionaries: token -> noun class.
const NOUNS: &[(Noun, &[&str])] = &[
    (
        Noun::File,
        &["file", "dir", "directory", "folder", "path", "fs", "filesystem", "notebook", "symlink", "workspace_file"],
    ),
    (
        Noun::Payment,
        &[
            "payment",
            "invoice",
            "payout",
            "refund",
            "charge",
            "transaction",
            "subscription",
            "paymentintent",
            "wire",
            "remittance",
            "disbursement",
            "money",
            "fund",
        ],
    ),
    (
        Noun::Identity,
        &[
            "user",
            "role",
            "permission",
            "member",
            "membership",
            "admin",
            "collaborator",
            "acl",
            "iam",
            "privilege",
            "owner",
            "ownership",
            "rolebinding",
            "serviceaccount",
        ],
    ),
    (Noun::Message, &["message", "email", "mail", "post", "tweet", "sms", "dm", "comment_reply", "status_update"]),
    (
        Noun::Secret,
        &[
            "secret",
            "credential",
            "password",
            "passwd",
            "passphrase",
            "vault",
            "keychain",
            "apikey",
            "privatekey",
            "kms",
            "keyring",
            "token",
        ],
    ),
    (Noun::Sql, &["sql", "query", "statement", "ddl", "dml"]),
];

/// Tokens that precede `key` to make it a credential (`api_key`, `ssh_key`).
const KEY_QUALIFIERS: &[&str] =
    &["api", "ssh", "private", "access", "secret", "signing", "encryption", "gpg", "pgp", "deploy", "master"];

/// Tokens that make `token` mean LLM or rate-limit tokens, not credentials.
const TOKEN_COUNTING: &[&str] = &["count", "usage", "limit", "budget", "estimate", "tokenize", "max"];

/// Fetch tokens that name the medium (`browser_click`, `http_post`) rather
/// than the action; they never act as the primary verb.
const FETCH_CONTEXT: &[&str] = &["browser", "web", "http", "https", "url", "webpage", "website"];

/// Tokens that make `transfer` mean moving an object rather than money.
const NON_MONEY_TRANSFER: &[&str] =
    &["file", "repo", "repository", "issue", "ownership", "domain", "project", "data", "call", "chat", "conversation"];

/// Input schema properties (folded like name tokens) and what they signal.
const PARAMS: &[(&str, &[&str])] = &[
    ("command", &["command", "cmd", "script", "shell_command", "bash_command", "commandline", "command_line"]),
    ("sql", &["sql", "query", "statement", "sql_query"]),
    ("url", &["url", "uri", "href", "link", "endpoint", "website", "webpage", "page_url"]),
    ("recipient", &["to", "recipient", "recipients", "cc", "bcc", "email_to", "chat_id", "channel_id", "phone_number"]),
    ("body", &["body", "message", "text", "subject", "content", "html", "markdown", "blocks"]),
    ("amount", &["amount", "amount_cents", "value_cents", "sum"]),
    (
        "account",
        &[
            "iban",
            "account",
            "account_number",
            "account_id",
            "routing_number",
            "bic",
            "swift",
            "beneficiary",
            "destination_account",
            "card",
            "card_number",
            "currency",
        ],
    ),
    ("path", &["path", "file_path", "filepath", "filename", "file", "directory", "dir", "paths", "source_path"]),
    ("secret", &["password", "secret", "api_key", "apikey", "private_key", "client_secret", "passphrase"]),
];

/// Description phrases used when the name and schema give nothing.
const DESCRIPTION_PHRASES: &[(Capability, &[&str])] = &[
    (
        Capability::CommandExecution,
        &[
            "shell command",
            "run a command",
            "runs a command",
            "execute a command",
            "executes a command",
            "arbitrary code",
        ],
    ),
    (
        Capability::ExternalSend,
        &["send an email", "sends an email", "send a message", "sends a message", "post a message", "posts a message"],
    ),
    (Capability::Payment, &["payment", "refund", "transfer money", "transfers money", "send money", "sends money"]),
    (Capability::DataDeletion, &["permanently delete", "permanently deletes", "permanently remove"]),
    (Capability::CredentialAccess, &["api key", "password", "secret value", "access token"]),
];

/// Built-in coding-agent tools on the `local` server (Claude Code, Cursor,
/// the names nandi's hook adapters use). Matched case-insensitively.
const LOCAL_TOOLS: &[(&str, &[Capability])] = &[
    ("bash", &[Capability::CommandExecution]),
    ("shell", &[Capability::CommandExecution]),
    ("run_terminal_cmd", &[Capability::CommandExecution]),
    ("bashoutput", &[Capability::ReadOnly]),
    ("killshell", &[Capability::CommandExecution]),
    ("write", &[Capability::FileWrite]),
    ("edit", &[Capability::FileWrite]),
    ("multiedit", &[Capability::FileWrite]),
    ("notebookedit", &[Capability::FileWrite]),
    ("edit_file", &[Capability::FileWrite]),
    ("write_file", &[Capability::FileWrite]),
    ("search_replace", &[Capability::FileWrite]),
    ("apply_patch", &[Capability::FileWrite]),
    ("delete_file", &[Capability::FileDelete]),
    ("webfetch", &[Capability::NetworkFetch]),
    ("websearch", &[Capability::NetworkFetch]),
    ("web_search", &[Capability::NetworkFetch]),
    ("read", &[Capability::ReadOnly]),
    ("read_file", &[Capability::ReadOnly]),
    ("notebookread", &[Capability::ReadOnly]),
    ("grep", &[Capability::ReadOnly]),
    ("grep_search", &[Capability::ReadOnly]),
    ("glob", &[Capability::ReadOnly]),
    ("file_search", &[Capability::ReadOnly]),
    ("codebase_search", &[Capability::ReadOnly]),
    ("ls", &[Capability::ReadOnly]),
    ("list_dir", &[Capability::ReadOnly]),
    ("task", &[]),
    ("agent", &[]),
    ("todowrite", &[]),
    ("todoread", &[]),
    ("exitplanmode", &[]),
    // Codex
    ("update_plan", &[]),
    ("spawn_agent", &[]),
    // Gemini CLI
    ("run_shell_command", &[Capability::CommandExecution]),
    // Windsurf (named by the nandi adapter)
    ("run_command", &[Capability::CommandExecution]),
    ("replace", &[Capability::FileWrite]),
    ("read_many_files", &[Capability::ReadOnly]),
    ("list_directory", &[Capability::ReadOnly]),
    ("web_fetch", &[Capability::NetworkFetch]),
    ("google_web_search", &[Capability::NetworkFetch]),
    ("write_todos", &[]),
    ("ask_user", &[]),
    // GitHub Copilot CLI
    ("powershell", &[Capability::CommandExecution]),
    ("view", &[Capability::ReadOnly]),
    ("create", &[Capability::FileWrite]),
    ("str_replace_editor", &[Capability::FileWrite]),
    ("update_todo", &[]),
    // Devin and Windsurf
    ("exec", &[Capability::CommandExecution]),
    ("write_to_process", &[Capability::CommandExecution]),
    ("get_output", &[Capability::ReadOnly]),
    ("kill_shell", &[Capability::CommandExecution]),
    ("notebook_read", &[Capability::ReadOnly]),
    ("notebook_edit", &[Capability::FileWrite]),
    ("todo_write", &[]),
];

/// A classification with an optional explanation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Classification {
    /// Sorted, without duplicates.
    pub capabilities: Vec<Capability>,
    /// Why annotations were overridden, when they were.
    pub note: Option<String>,
}

/// Capabilities of a tool from its definition.
pub fn classify(tool: &ToolDef) -> Vec<Capability> {
    classify_detailed(tool).capabilities
}

/// [`classify`] with the annotation note.
pub fn classify_detailed(tool: &ToolDef) -> Classification {
    let tokens = tokenize(&tool.name);
    let params = param_tokens(&tool.input_schema);
    let mut caps = infer(&tokens, &params, &[]);
    if caps.is_empty() {
        caps = from_description(&tool.description);
    }
    let mut note = None;
    let hint = |k: &str| tool.annotations.get(k).and_then(Value::as_bool) == Some(true);
    if hint("readOnlyHint") {
        let dangerous: Vec<Capability> =
            caps.iter().copied().filter(|c| c.weight() >= 20 && *c != Capability::ReadOnly).collect();
        if dangerous.is_empty() {
            caps = vec![Capability::ReadOnly];
        } else {
            let names: Vec<&str> = dangerous.iter().map(Capability::as_str).collect();
            note = Some(format!("readOnlyHint ignored: the name suggests {}", names.join(", ")));
            caps = dangerous;
        }
    } else {
        if hint("destructiveHint") && caps.is_empty() {
            caps.push(Capability::DataDeletion);
        }
        if hint("openWorldHint") {
            caps.retain(|c| *c != Capability::ReadOnly);
            caps.push(Capability::NetworkFetch);
        }
    }
    Classification { capabilities: finish(caps), note }
}

/// Capabilities of a tool known only by name. Built-in tools of the
/// `local` server are mapped explicitly; other names go through the same
/// dictionaries as [`classify`], with the server name as file context
/// (`filesystem/write` writes files).
pub fn classify_name(server: &str, tool: &str) -> Vec<Capability> {
    if server == LOCAL_SERVER
        && let Some((_, caps)) = LOCAL_TOOLS.iter().find(|(n, _)| n.eq_ignore_ascii_case(tool))
    {
        return caps.to_vec();
    }
    let server_tokens = if server == LOCAL_SERVER { Vec::new() } else { tokenize(server) };
    finish(infer(&tokenize(tool), &[], &server_tokens))
}

fn finish(mut caps: Vec<Capability>) -> Vec<Capability> {
    caps.sort_unstable();
    caps.dedup();
    if caps.len() > 1 {
        caps.retain(|c| *c != Capability::ReadOnly);
    }
    caps
}

/// Split a name into lowercase singular tokens at separators and camelCase
/// boundaries.
pub fn tokenize(name: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    for part in name.split(|c: char| !c.is_alphanumeric()) {
        let chars: Vec<char> = part.chars().collect();
        let mut cur = String::new();
        for (i, &c) in chars.iter().enumerate() {
            let prev = i.checked_sub(1).map(|j| chars[j]);
            let next = chars.get(i + 1).copied();
            let boundary = match prev {
                Some(p) if c.is_uppercase() => {
                    p.is_lowercase() || p.is_ascii_digit() || (p.is_uppercase() && next.is_some_and(char::is_lowercase))
                }
                _ => false,
            };
            if boundary && !cur.is_empty() {
                words.push(std::mem::take(&mut cur));
            }
            cur.extend(c.to_lowercase());
        }
        if !cur.is_empty() {
            words.push(cur);
        }
    }
    words.into_iter().map(|w| singular(&w)).collect()
}

fn singular(w: &str) -> String {
    if w.len() > 4
        && let Some(stem) = w.strip_suffix("ies")
    {
        return format!("{stem}y");
    }
    if w.len() > 4 && (w.ends_with("sses") || w.ends_with("shes") || w.ends_with("ches") || w.ends_with("xes")) {
        return w[..w.len() - 2].to_string();
    }
    if w.len() > 3 && w.ends_with('s') && !w.ends_with("ss") && !w.ends_with("us") && !w.ends_with("is") {
        return w[..w.len() - 1].to_string();
    }
    w.to_string()
}

fn verb_of(token: &str) -> Option<Verb> {
    VERBS.iter().find(|(_, words)| words.contains(&token)).map(|(v, _)| *v)
}

fn has_noun(tokens: &[String], noun: Noun) -> bool {
    NOUNS.iter().filter(|(n, _)| *n == noun).any(|(_, words)| tokens.iter().any(|t| words.contains(&t.as_str())))
}

fn has_any(tokens: &[String], words: &[&str]) -> bool {
    tokens.iter().any(|t| words.contains(&t.as_str()))
}

/// Folded top-level input schema property names, grouped by [`PARAMS`]
/// class.
fn param_tokens(schema: &Value) -> Vec<&'static str> {
    let Some(props) = schema.get("properties").and_then(Value::as_object) else { return Vec::new() };
    let mut out = Vec::new();
    for key in props.keys() {
        let folded = tokenize(key).join("_");
        for (class, names) in PARAMS {
            if names.contains(&folded.as_str()) || names.contains(&key.to_ascii_lowercase().as_str()) {
                out.push(*class);
            }
        }
    }
    out
}

fn credential_tokens(tokens: &[String]) -> bool {
    let secret = NOUNS.iter().find(|(n, _)| *n == Noun::Secret).map_or(&[][..], |(_, w)| *w);
    let counting = has_any(tokens, TOKEN_COUNTING);
    tokens.iter().enumerate().any(|(i, t)| {
        (secret.contains(&t.as_str()) && !(t == "token" && counting))
            || (t == "key" && i > 0 && KEY_QUALIFIERS.contains(&tokens[i - 1].as_str()))
    })
}

fn infer(tokens: &[String], params: &[&str], context: &[String]) -> Vec<Capability> {
    use Capability::*;
    let param = |class: &str| params.contains(&class);
    let mut verbs: Vec<Verb> = tokens.iter().filter_map(|t| verb_of(t)).collect();
    // `transfer` of files, repositories or ownership is not a payment.
    if tokens.iter().any(|t| t == "transfer") && !has_any(tokens, NON_MONEY_TRANSFER) {
        verbs.push(Verb::Pay);
    }
    let primary = tokens.iter().filter(|t| !FETCH_CONTEXT.contains(&t.as_str())).find_map(|t| verb_of(t));
    let reads_first = matches!(primary, Some(Verb::Read | Verb::Fetch));
    let has = |v: Verb| verbs.contains(&v);
    let mutates = has(Verb::Write) || has(Verb::Delete) || has(Verb::Send) || has(Verb::Pay) || has(Verb::Grant);
    let file_ctx = has_noun(tokens, Noun::File) || param("path") || has_noun(context, Noun::File);
    let sql_ctx = has_noun(tokens, Noun::Sql) || param("sql");

    let mut caps = Vec::new();
    let mut domain_write = false;

    // Commands and code. Executing SQL changes and deletes data instead.
    if has(Verb::Exec) || param("command") {
        if sql_ctx && !param("command") {
            caps.extend([DataModification, DataDeletion]);
        } else {
            caps.push(CommandExecution);
        }
    } else if sql_ctx && param("sql") && (has(Verb::Write) || has(Verb::Delete)) {
        caps.push(DataModification);
        if has(Verb::Delete) {
            caps.push(DataDeletion);
        }
    }

    if credential_tokens(tokens) || param("secret") {
        caps.push(CredentialAccess);
    }

    if !reads_first {
        if has(Verb::Pay) || (has_noun(tokens, Noun::Payment) && mutates) || (param("amount") && param("account")) {
            caps.push(Payment);
            domain_write = true;
        }
        if has(Verb::Grant) || (has_noun(tokens, Noun::Identity) && mutates) {
            caps.push(IdentityAdmin);
            domain_write = true;
        }
        // Message nouns (`email`, `post`) only send as the primary verb
        // (`email_report`) or with a write (`create_post`); `delete_email`
        // does not send anything.
        let message = NOUNS.iter().find(|(n, _)| *n == Noun::Message).map_or(&[][..], |(_, w)| *w);
        let sends = primary == Some(Verb::Send)
            || tokens.iter().any(|t| verb_of(t) == Some(Verb::Send) && !message.contains(&t.as_str()));
        if sends
            || (has_noun(tokens, Noun::Message) && has(Verb::Write))
            || (param("recipient") && param("body") && primary.is_none_or(|v| v != Verb::Read))
        {
            caps.push(ExternalSend);
            domain_write = true;
        }
        if has(Verb::Delete) && !has_noun(tokens, Noun::Identity) {
            caps.push(if file_ctx { FileDelete } else { DataDeletion });
        }
        if has(Verb::Write) && !domain_write && !caps.contains(&DataModification) {
            caps.push(if file_ctx { FileWrite } else { DataModification });
        }
    }

    if has(Verb::Fetch) || (param("url") && !caps.contains(&ExternalSend)) {
        caps.push(NetworkFetch);
    }
    if caps.is_empty() && has(Verb::Read) {
        caps.push(ReadOnly);
    }
    caps
}

fn from_description(description: &str) -> Vec<Capability> {
    let d = description.to_lowercase();
    DESCRIPTION_PHRASES.iter().filter(|(_, phrases)| phrases.iter().any(|p| d.contains(p))).map(|(c, _)| *c).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use Capability::*;
    use serde_json::json;

    fn tool(name: &str, description: &str, schema: Value, annotations: Value) -> ToolDef {
        ToolDef { name: name.into(), description: description.into(), input_schema: schema, annotations }
    }

    fn props(keys: &[&str]) -> Value {
        let p: serde_json::Map<String, Value> =
            keys.iter().map(|k| ((*k).to_string(), json!({"type": "string"}))).collect();
        json!({"type": "object", "properties": p})
    }

    #[test]
    fn tokenizes_snake_kebab_and_camel_case() {
        assert_eq!(tokenize("createPullRequest"), ["create", "pull", "request"]);
        assert_eq!(tokenize("list_S3Buckets"), ["list", "s3", "bucket"]);
        assert_eq!(tokenize("HTTPGet"), ["http", "get"]);
        assert_eq!(tokenize("browser-navigate.v2"), ["browser", "navigate", "v2"]);
        assert_eq!(tokenize("list_policies"), ["list", "policy"]);
        assert_eq!(tokenize("get_status"), ["get", "status"]);
        assert_eq!(tokenize("search_messages"), ["search", "message"]);
        assert_eq!(tokenize("process"), ["process"]);
    }

    /// (name, description, schema properties, annotations, expected).
    type Case = (&'static str, &'static str, &'static [&'static str], Value, &'static [Capability]);

    #[test]
    fn realistic_tool_table() {
        let none = Value::Null;
        let cases: Vec<Case> = vec![
            // GitHub
            (
                "create_issue",
                "Create a new issue in a GitHub repository",
                &["owner", "repo", "title", "body"],
                none.clone(),
                &[DataModification],
            ),
            ("list_issues", "List issues in a repository", &["owner", "repo"], none.clone(), &[ReadOnly]),
            ("get_file_contents", "Get the contents of a file", &["owner", "repo", "path"], none.clone(), &[ReadOnly]),
            (
                "push_files",
                "Push multiple files in a single commit",
                &["owner", "repo", "files"],
                none.clone(),
                &[FileWrite],
            ),
            (
                "create_or_update_file",
                "Create or update a single file",
                &["owner", "repo", "path", "content"],
                none.clone(),
                &[FileWrite],
            ),
            (
                "merge_pull_request",
                "Merge a pull request",
                &["owner", "repo", "pull_number"],
                none.clone(),
                &[DataModification],
            ),
            ("search_repositories", "Search for GitHub repositories", &["query"], none.clone(), &[NetworkFetch]),
            (
                "add_collaborator",
                "Add a user as a repository collaborator",
                &["owner", "repo", "username"],
                none.clone(),
                &[IdentityAdmin],
            ),
            ("delete_repository", "Delete a repository", &["owner", "repo"], none.clone(), &[DataDeletion]),
            (
                "create_or_update_secret",
                "Create or update a repository Actions secret",
                &["name", "value"],
                none.clone(),
                &[DataModification, CredentialAccess],
            ),
            // Slack
            (
                "slack_post_message",
                "Post a new message to a Slack channel",
                &["channel_id", "text"],
                none.clone(),
                &[ExternalSend],
            ),
            (
                "slack_reply_to_thread",
                "Reply to a specific message thread",
                &["channel_id", "thread_ts", "text"],
                none.clone(),
                &[ExternalSend],
            ),
            (
                "slack_get_channel_history",
                "Get recent messages from a channel",
                &["channel_id"],
                none.clone(),
                &[ReadOnly],
            ),
            ("slack_list_channels", "List public channels", &[], none.clone(), &[ReadOnly]),
            (
                "slack_invite_user",
                "Invite a user to a workspace",
                &["email"],
                none.clone(),
                &[ExternalSend, IdentityAdmin],
            ),
            // Stripe
            ("create_refund", "Refund a PaymentIntent", &["payment_intent", "amount"], none.clone(), &[Payment]),
            ("create_payment_link", "Create a payment link", &["price", "quantity"], none.clone(), &[Payment]),
            ("list_invoices", "List invoices", &["customer"], none.clone(), &[ReadOnly]),
            ("create_invoice", "Create an invoice for a customer", &["customer"], none.clone(), &[Payment]),
            ("capture_payment_intent", "Capture a PaymentIntent payment", &["id"], none.clone(), &[Payment]),
            ("transfer_funds", "Move money between accounts", &["amount", "iban"], none.clone(), &[Payment]),
            ("retrieve_balance", "Retrieve the account balance", &[], none.clone(), &[ReadOnly]),
            // Filesystem
            ("read_file", "Read the complete contents of a file", &["path"], none.clone(), &[ReadOnly]),
            (
                "write_file",
                "Create a new file or overwrite an existing one",
                &["path", "content"],
                none.clone(),
                &[FileWrite],
            ),
            ("edit_file", "Make line-based edits to a text file", &["path", "edits"], none.clone(), &[FileWrite]),
            (
                "move_file",
                "Move or rename files and directories",
                &["source", "destination"],
                none.clone(),
                &[FileWrite],
            ),
            ("delete_file", "Delete a file", &["path"], none.clone(), &[FileDelete]),
            ("list_directory", "List directory contents", &["path"], none.clone(), &[ReadOnly]),
            ("create_directory", "Create a directory", &["path"], none.clone(), &[FileWrite]),
            // Postgres / Supabase
            ("query", "Run a read-only SQL query", &["sql"], none.clone(), &[ReadOnly]),
            (
                "execute_sql",
                "Executes raw SQL in the database",
                &["query"],
                none.clone(),
                &[DataModification, DataDeletion],
            ),
            ("insert_rows", "Insert rows into a table", &["table", "rows"], none.clone(), &[DataModification]),
            ("drop_table", "Drop a table", &["table"], none.clone(), &[DataDeletion]),
            ("truncate_table", "Remove all rows", &["table"], none.clone(), &[DataDeletion]),
            // Browser (Playwright, Puppeteer, fetch)
            ("browser_navigate", "Navigate to a URL", &["url"], none.clone(), &[NetworkFetch]),
            (
                "browser_click",
                "Click an element on the page",
                &["element", "ref"],
                none.clone(),
                &[NetworkFetch, DataModification],
            ),
            (
                "browser_evaluate",
                "Evaluate JavaScript on the page",
                &["function"],
                none.clone(),
                &[NetworkFetch, CommandExecution],
            ),
            ("fetch", "Fetches a URL from the internet", &["url", "max_length"], none.clone(), &[NetworkFetch]),
            ("download_file", "Download a file", &["url", "path"], none.clone(), &[NetworkFetch]),
            // Gmail
            ("gmail_send_email", "Send an email", &["to", "subject", "body"], none.clone(), &[ExternalSend]),
            ("search_emails", "Search emails using Gmail search syntax", &["query"], none.clone(), &[NetworkFetch]),
            ("read_email", "Read a specific email", &["messageId"], none.clone(), &[ReadOnly]),
            ("draft_email", "Draft a new email", &["to", "subject", "body"], none.clone(), &[ExternalSend]),
            ("delete_email", "Permanently delete an email", &["messageId"], none.clone(), &[DataDeletion]),
            // Shells, interpreters, secrets, identity, misc
            ("run_command", "Run a shell command", &["command"], none.clone(), &[CommandExecution]),
            ("execute_python", "Execute Python code in a sandbox", &["code"], none.clone(), &[CommandExecution]),
            ("kubectl_exec", "Exec into a pod", &["pod", "command"], none.clone(), &[CommandExecution]),
            ("get_secret", "Read a secret from the vault", &["name"], none.clone(), &[CredentialAccess]),
            ("vault_read", "Read a Vault path", &["path"], none.clone(), &[CredentialAccess]),
            ("rotate_api_key", "Rotate an API key", &["key_id"], none.clone(), &[CredentialAccess]),
            ("count_tokens", "Count LLM tokens in text", &["text"], none.clone(), &[ReadOnly]),
            ("assign_role", "Assign a role to a user", &["user", "role"], none.clone(), &[IdentityAdmin]),
            ("revoke_access", "Revoke a user's access", &["user"], none.clone(), &[IdentityAdmin]),
            ("list_users", "List users", &[], none.clone(), &[ReadOnly]),
            ("notify_oncall", "Page the on-call engineer", &["summary"], none.clone(), &[ExternalSend]),
            ("trigger_webhook", "Call a webhook", &["url", "payload"], none.clone(), &[ExternalSend]),
            (
                "transfer_issue",
                "Transfer an issue to another repository",
                &["issue"],
                none.clone(),
                &[DataModification],
            ),
            ("add", "Adds two numbers", &["a", "b"], none.clone(), &[DataModification]),
            ("echo", "Echo the input", &["text"], none.clone(), &[]),
            ("mystery", "Runs a shell command on the host", &["input"], none.clone(), &[CommandExecution]),
            ("send", "Sends a message", &["to", "body"], none.clone(), &[ExternalSend]),
            ("notify", "Notify", &["recipient", "message"], none.clone(), &[ExternalSend]),
            ("lookup", "Look up a customer", &["to", "message"], none.clone(), &[ReadOnly]),
        ];
        assert!(cases.len() >= 40);
        let mut failures = Vec::new();
        for (name, desc, keys, ann, want) in &cases {
            let got = classify(&tool(name, desc, props(keys), ann.clone()));
            if got != *want {
                failures.push(format!("{name}: got {got:?}, want {want:?}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn annotations() {
        let ro = json!({"readOnlyHint": true});
        let c = classify_detailed(&tool("create_report", "", props(&[]), ro.clone()));
        assert_eq!(c.capabilities, [ReadOnly]);
        assert!(c.note.is_none());
        // A dangerous name wins over a read-only hint, with a note.
        let c = classify_detailed(&tool("run_shell", "", props(&["command"]), ro.clone()));
        assert_eq!(c.capabilities, [CommandExecution]);
        assert!(c.note.as_deref().unwrap().contains("command_execution"), "{c:?}");
        let c = classify_detailed(&tool("gizmo", "", props(&[]), json!({"destructiveHint": true})));
        assert_eq!(c.capabilities, [DataDeletion]);
        let c = classify_detailed(&tool("drop_cache", "", props(&[]), json!({"destructiveHint": true})));
        assert_eq!(c.capabilities, [DataDeletion]);
        let c = classify(&tool("get_weather", "", props(&["city"]), json!({"openWorldHint": true})));
        assert_eq!(c, [NetworkFetch]);
        let c = classify(&tool("send_email", "", props(&[]), json!({"openWorldHint": true, "readOnlyHint": false})));
        assert_eq!(c, [NetworkFetch, ExternalSend]);
    }

    #[test]
    fn names_only() {
        assert_eq!(classify_name(LOCAL_SERVER, "Bash"), [CommandExecution]);
        assert_eq!(classify_name(LOCAL_SERVER, "shell"), [CommandExecution]);
        assert_eq!(classify_name(LOCAL_SERVER, "Write"), [FileWrite]);
        assert_eq!(classify_name(LOCAL_SERVER, "MultiEdit"), [FileWrite]);
        assert_eq!(classify_name(LOCAL_SERVER, "NotebookEdit"), [FileWrite]);
        assert_eq!(classify_name(LOCAL_SERVER, "edit_file"), [FileWrite]);
        assert_eq!(classify_name(LOCAL_SERVER, "WebFetch"), [NetworkFetch]);
        assert_eq!(classify_name(LOCAL_SERVER, "WebSearch"), [NetworkFetch]);
        assert_eq!(classify_name(LOCAL_SERVER, "Read"), [ReadOnly]);
        assert_eq!(classify_name(LOCAL_SERVER, "Grep"), [ReadOnly]);
        assert_eq!(classify_name(LOCAL_SERVER, "Glob"), [ReadOnly]);
        assert_eq!(classify_name(LOCAL_SERVER, "LS"), [ReadOnly]);
        assert!(classify_name(LOCAL_SERVER, "Task").is_empty());
        // Local tools requested by a model fall back to the dictionaries.
        assert_eq!(classify_name(LOCAL_SERVER, "send_money"), [ExternalSend, Payment]);
        assert_eq!(classify_name(LOCAL_SERVER, "make_payment"), [Payment]);
        assert_eq!(classify_name("github", "create_pull_request"), [DataModification]);
        assert_eq!(classify_name("filesystem", "write"), [FileWrite]);
        assert_eq!(classify_name("stripe", "refund"), [Payment]);
        assert_eq!(classify_name("x", "frobnicate"), Vec::<Capability>::new());
    }
}
