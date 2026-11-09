//! End-to-end tests of the `nandi` binary.

use std::path::Path;
use std::process::{Command, Output};

fn nandi(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nandi"))
        .args(args)
        .current_dir(dir)
        .env_remove("NANDI_CONFIG")
        .env_remove("NANDI_ADMIN_TOKEN")
        .output()
        .expect("running nandi")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn ok(o: Output) -> String {
    assert!(
        o.status.success(),
        "status {:?}\nstdout: {}\nstderr: {}",
        o.status,
        stdout(&o),
        String::from_utf8_lossy(&o.stderr)
    );
    stdout(&o)
}

#[test]
fn init_then_validate() {
    let dir = tempfile::tempdir().unwrap();
    ok(nandi(dir.path(), &["init", "--dir", "."]));
    assert!(dir.path().join("policies/policy.cedar").exists());
    let out = ok(nandi(dir.path(), &["policy", "validate"]));
    assert!(out.contains("ok:"), "{out}");
    assert!(out.contains("0 warning(s)"), "{out}");
    // A second init refuses to overwrite.
    assert!(!nandi(dir.path(), &["init", "--dir", "."]).status.success());
    ok(nandi(dir.path(), &["init", "--dir", ".", "--force"]));
}

#[test]
fn validate_reports_broken_policy() {
    let dir = tempfile::tempdir().unwrap();
    ok(nandi(dir.path(), &["init"]));
    std::fs::write(dir.path().join("policies/rules.yaml"), "rules:\n  - id: x\n    mtach: {}\n").unwrap();
    let o = nandi(dir.path(), &["-c", "nandi.yaml", "policy", "validate"]);
    assert!(!o.status.success());
}

#[test]
fn key_hash_is_sha256() {
    let dir = tempfile::tempdir().unwrap();
    let out = ok(nandi(dir.path(), &["key", "hash", "abc"]));
    assert_eq!(out.trim(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let out = ok(nandi(dir.path(), &["key", "generate"]));
    assert!(out.contains("sha256: "), "{out}");
}

#[test]
fn token_keygen_mint_attenuate_inspect() {
    let dir = tempfile::tempdir().unwrap();
    let keys = ok(nandi(dir.path(), &["token", "keygen"]));
    let field = |name: &str| -> String {
        keys.lines().find_map(|l| l.strip_prefix(name)).map(|v| v.trim().to_string()).expect(name)
    };
    let (private, public) = (field("private:"), field("public:"));
    let token = ok(nandi(
        dir.path(),
        &["token", "mint", "--private-key", &private, "--agent", "planner", "--tool", "github/*", "--ttl", "600"],
    ));
    let token = token.trim();
    let narrowed = ok(nandi(
        dir.path(),
        &["token", "attenuate", "--token", token, "--public-key", &public, "--tool", "github/get_issue"],
    ));
    let out = ok(nandi(dir.path(), &["token", "inspect", "--token", narrowed.trim()]));
    assert!(out.contains("planner"), "{out}");
    assert!(out.contains("github/get_issue"), "{out}");
}

#[test]
fn policy_test_shows_deny() {
    let dir = tempfile::tempdir().unwrap();
    ok(nandi(dir.path(), &["init"]));
    let events = [
        r#"{"kind":{"type":"tool_call","server":"shell","tool":"run","args":{"command":"rm -rf /srv/data"}}}"#,
        r#"{"kind":{"type":"tool_call","server":"shell","tool":"run","args":{"command":"ls"}}}"#,
        r#"{"event":{"agent":"i1","kind":{"type":"tool_call","server":"github","tool":"delete_repository","args":{}}},"groups":["interns"]}"#,
    ];
    std::fs::write(dir.path().join("events.jsonl"), events.join("\n")).unwrap();
    let out = ok(nandi(dir.path(), &["policy", "test", "--events", "events.jsonl"]));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(lines[0].contains("deny") && lines[0].contains("no-rm-rf"), "{out}");
    assert!(lines[1].contains("allow"), "{out}");
    assert!(lines[2].contains("deny") && lines[2].contains("interns-no-repo-delete"), "{out}");

    let out = ok(nandi(dir.path(), &["policy", "test", "--events", "events.jsonl", "--json"]));
    let first: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    assert_eq!(first["verdict"], "deny");
}

#[test]
fn version_prints() {
    let dir = tempfile::tempdir().unwrap();
    assert!(ok(nandi(dir.path(), &["version"])).starts_with("nandi "));
}
