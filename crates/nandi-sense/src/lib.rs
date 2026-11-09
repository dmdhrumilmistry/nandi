//! Host sensor: observe what agent processes actually do.
//!
//! Proxies and hooks see what an agent *asks* for; this crate watches what
//! its process tree *does* (AgentSight's boundary tracing): processes it
//! spawns, sensitive files it opens and hosts it connects to. Events are
//! emitted as ordinary [`nandi_core::Event`]s (`process`, `file`,
//! `network`) and the engine correlates them with the tool calls it saw.
//!
//! Backends:
//! - `procfs` (Linux, default): polls `/proc`. Needs no privileges for the
//!   user's own processes and no kernel features, but can miss very
//!   short-lived processes and files.
//! - `ebpf` (Linux, cargo feature `ebpf`): kernel tracepoints for exec,
//!   openat and connect delivered through a ring buffer. Catches everything,
//!   needs root (or CAP_BPF + CAP_PERFMON) and kernel 5.8+.

use std::collections::{HashMap, HashSet};

use nandi_core::config::SensorConfig;
use nandi_core::util::glob_match;
use nandi_core::{Event, EventKind, FileEvent, NetworkEvent, ProcessEvent, Source};

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod ebpf;
#[cfg(target_os = "linux")]
pub mod procfs;

/// One process as seen by a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: String,
    pub argv: Vec<String>,
}

/// Agent attribution and de-duplication shared by all backends.
///
/// A process belongs to an agent when it, or one of its ancestors, matches
/// `agent_comms` (by comm, executable name or the first two argv entries,
/// so `node /usr/bin/claude` is recognised).
#[derive(Debug)]
pub struct Tracker {
    cfg: SensorConfig,
    procs: HashMap<u32, ProcInfo>,
    /// pid -> agent root pid (cached attribution).
    roots: HashMap<u32, Option<u32>>,
    seen_files: HashSet<(u32, String)>,
    seen_conns: HashSet<(u32, String, u16)>,
    /// IP -> host name for `llm_hosts` (filled by the backend's resolver).
    host_by_ip: HashMap<String, String>,
    own_pid: u32,
}

impl Tracker {
    pub fn new(cfg: SensorConfig) -> Self {
        Self {
            cfg,
            procs: HashMap::new(),
            roots: HashMap::new(),
            seen_files: HashSet::new(),
            seen_conns: HashSet::new(),
            host_by_ip: HashMap::new(),
            own_pid: std::process::id(),
        }
    }

    pub fn config(&self) -> &SensorConfig {
        &self.cfg
    }

    /// Record resolved addresses of a known host.
    pub fn learn_host(&mut self, host: &str, ips: impl IntoIterator<Item = String>) {
        for ip in ips {
            self.host_by_ip.insert(ip, host.to_string());
        }
    }

    fn is_agent(&self, p: &ProcInfo) -> bool {
        let exe_name = p.exe.rsplit('/').next().unwrap_or("");
        let args: Vec<&str> = p.argv.iter().take(2).map(|a| a.rsplit('/').next().unwrap_or(a.as_str())).collect();
        self.cfg
            .agent_comms
            .iter()
            .any(|c| glob_match(c, &p.comm) || glob_match(c, exe_name) || args.iter().any(|a| glob_match(c, a)))
    }

    /// Agent root pid of `pid`, walking up through known parents. The
    /// outermost agent process in the chain is the root, so `claude` ->
    /// `node` -> `claude-helper` all map to one agent.
    pub fn agent_root(&mut self, pid: u32) -> Option<u32> {
        if let Some(r) = self.roots.get(&pid) {
            return *r;
        }
        let mut chain: Vec<u32> = Vec::new();
        // Index in `chain` of the outermost agent found so far.
        let mut root_at: Option<usize> = None;
        let mut inherited: Option<u32> = None;
        let mut cur = pid;
        for _ in 0..64 {
            if cur != pid
                && let Some(r) = self.roots.get(&cur)
            {
                // Everything below a cached agent tree belongs to it.
                inherited = *r;
                break;
            }
            let Some(p) = self.procs.get(&cur) else { break };
            if p.pid == self.own_pid {
                break;
            }
            chain.push(cur);
            if self.is_agent(p) {
                root_at = Some(chain.len() - 1);
            }
            if p.ppid == 0 || p.ppid == cur {
                break;
            }
            cur = p.ppid;
        }
        let root = inherited.or(root_at.map(|i| chain[i]));
        for (i, c) in chain.iter().enumerate() {
            // Non-agent ancestors above the root are not part of the tree.
            let value = if inherited.is_some() || root_at.is_some_and(|r| i <= r) { root } else { None };
            self.roots.insert(*c, value);
        }
        root
    }

    fn agent_name(&self, root: u32) -> String {
        self.procs
            .get(&root)
            .map(|p| {
                self.cfg
                    .agent_comms
                    .iter()
                    .find(|c| {
                        glob_match(c, &p.comm)
                            || glob_match(c, p.exe.rsplit('/').next().unwrap_or(""))
                            || p.argv.iter().take(2).any(|a| glob_match(c, a.rsplit('/').next().unwrap_or(a)))
                    })
                    .cloned()
                    .unwrap_or_else(|| p.comm.clone())
            })
            .unwrap_or_else(|| "unknown-agent".into())
    }

    fn event(&self, root: u32, kind: EventKind) -> Event {
        Event::new(Source::Sensor, self.agent_name(root), format!("pid:{root}"), kind)
    }

    /// A process appeared (exec). Returns an event when it belongs to an
    /// agent tree and is not the agent root itself.
    pub fn on_exec(&mut self, p: ProcInfo) -> Option<Event> {
        let pid = p.pid;
        self.roots.remove(&pid);
        self.procs.insert(pid, p.clone());
        let root = self.agent_root(pid)?;
        if root == pid {
            return None;
        }
        Some(self.event(
            root,
            EventKind::Process(ProcessEvent {
                pid,
                ppid: p.ppid,
                uid: p.uid,
                comm: p.comm,
                filename: p.exe,
                argv: p.argv,
            }),
        ))
    }

    /// A process exited.
    pub fn on_exit(&mut self, pid: u32) {
        self.procs.remove(&pid);
        self.roots.remove(&pid);
        self.seen_files.retain(|(p, _)| *p != pid);
        self.seen_conns.retain(|(p, _, _)| *p != pid);
    }

    /// A file was opened. Only sensitive paths opened by agent trees are
    /// reported, once per (pid, path).
    pub fn on_open(&mut self, pid: u32, path: &str, write: bool) -> Option<Event> {
        if !self.cfg.sensitive_paths.iter().any(|g| glob_match(g, path)) {
            return None;
        }
        let root = self.agent_root(pid)?;
        if !self.seen_files.insert((pid, path.to_string())) {
            return None;
        }
        let comm = self.procs.get(&pid).map(|p| p.comm.clone()).unwrap_or_default();
        Some(self.event(root, EventKind::File(FileEvent { pid, comm, path: path.to_string(), write })))
    }

    /// An outbound connection. Reported once per (pid, address, port) for
    /// agent trees; the host name is filled in when known.
    pub fn on_connect(&mut self, pid: u32, daddr: &str, dport: u16, host: Option<String>) -> Option<Event> {
        if daddr.starts_with("127.") || daddr == "::1" || daddr.is_empty() {
            return None;
        }
        let root = self.agent_root(pid)?;
        if !self.seen_conns.insert((pid, daddr.to_string(), dport)) {
            return None;
        }
        let comm = self.procs.get(&pid).map(|p| p.comm.clone()).unwrap_or_default();
        let host = host.or_else(|| self.host_by_ip.get(daddr).cloned());
        Some(self.event(root, EventKind::Network(NetworkEvent { pid, comm, daddr: daddr.to_string(), dport, host })))
    }

    pub fn known_pids(&self) -> impl Iterator<Item = &u32> {
        self.procs.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, ppid: u32, comm: &str, exe: &str, argv: &[&str]) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            uid: 1000,
            comm: comm.into(),
            exe: exe.into(),
            argv: argv.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn tracker() -> Tracker {
        Tracker::new(SensorConfig { enabled: true, ..SensorConfig::default() })
    }

    #[test]
    fn attributes_children_of_agents() {
        let mut t = tracker();
        assert!(t.on_exec(p(10, 1, "bash", "/bin/bash", &["bash"])).is_none());
        // `node /usr/local/bin/claude` is recognised through argv.
        assert!(t.on_exec(p(20, 10, "node", "/usr/bin/node", &["node", "/usr/local/bin/claude"])).is_none());
        let ev = t.on_exec(p(30, 20, "curl", "/usr/bin/curl", &["curl", "https://x.example"])).unwrap();
        assert_eq!(ev.agent, "claude");
        assert_eq!(ev.session, "pid:20");
        assert!(matches!(ev.kind, EventKind::Process(ref pe) if pe.filename == "/usr/bin/curl"));
        // Unrelated processes are ignored.
        assert!(t.on_exec(p(40, 10, "vim", "/usr/bin/vim", &["vim"])).is_none());
    }

    #[test]
    fn reports_sensitive_files_once() {
        let mut t = tracker();
        t.on_exec(p(20, 1, "codex", "/usr/bin/codex", &["codex"]));
        t.on_exec(p(21, 20, "python3", "/usr/bin/python3", &["python3", "x.py"]));
        assert!(t.on_open(21, "/home/u/project/src/main.rs", false).is_none());
        let ev = t.on_open(21, "/home/u/.aws/credentials", false).unwrap();
        assert!(matches!(ev.kind, EventKind::File(ref f) if f.comm == "python3"));
        assert!(t.on_open(21, "/home/u/.aws/credentials", false).is_none());
        t.on_exit(21);
        assert!(t.on_open(21, "/home/u/.aws/credentials", false).is_none(), "unknown pid after exit");
    }

    #[test]
    fn connections_resolve_known_hosts() {
        let mut t = tracker();
        t.learn_host("api.openai.com", ["104.18.7.192".to_string()]);
        t.on_exec(p(50, 1, "aider", "/usr/bin/python3", &["python3", "/usr/bin/aider"]));
        let ev = t.on_connect(50, "104.18.7.192", 443, None).unwrap();
        assert!(matches!(ev.kind, EventKind::Network(ref n) if n.host.as_deref() == Some("api.openai.com")));
        assert!(t.on_connect(50, "104.18.7.192", 443, None).is_none());
        assert!(t.on_connect(50, "127.0.0.1", 8787, None).is_none());
    }
}
