//! Kernel records of the eBPF backend and their translation into
//! [`Tracker`] calls.
//!
//! Decoding and enrichment live here, outside the `ebpf` feature, so they
//! are tested on every build. The layouts mirror `bpf/sense.bpf.c`, whose
//! `_Static_assert`s pin the offsets used below.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};

use nandi_core::Event;

use crate::procfs::{list_pids, read_proc};
use crate::{ProcInfo, Tracker};

pub const REC_EXEC: u32 = 1;
pub const REC_OPEN: u32 = 2;
pub const REC_CONNECT: u32 = 3;
pub const REC_EXIT: u32 = 4;

const HDR_SIZE: usize = 16;
const COMM_LEN: usize = 16;
const PATH_LEN: usize = 256;
const ARG_LEN: usize = 128;
const MAX_ARGS: usize = 8;
pub const EXEC_SIZE: usize = 1320;
pub const OPEN_SIZE: usize = 280;
pub const CONNECT_SIZE: usize = 40;

const AT_FDCWD: i32 = -100;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Fields every record starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Thread group id (the process id).
    pub pid: u32,
    /// Parent tgid as tracked by the kernel side, 0 when unknown.
    pub ppid: u32,
    pub uid: u32,
}

/// One decoded kernel record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A successful execve/execveat.
    Exec {
        hdr: Header,
        comm: String,
        filename: String,
        argv: Vec<String>,
        /// argv had more entries than the kernel side captures.
        truncated: bool,
    },
    /// An open attempt by a watched process.
    Open { hdr: Header, dfd: i32, flags: u32, path: String },
    /// A connect by a watched process.
    Connect { hdr: Header, addr: IpAddr, port: u16 },
    /// A process (thread group leader) exited.
    Exit { hdr: Header },
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(b[off..off + 4].try_into().expect("4 bytes"))
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

impl Record {
    /// Decode one ring buffer record; `None` for unknown or short records.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < HDR_SIZE {
            return None;
        }
        let hdr = Header { pid: u32_at(b, 4), ppid: u32_at(b, 8), uid: u32_at(b, 12) };
        match u32_at(b, 0) {
            REC_EXEC if b.len() >= EXEC_SIZE => {
                let argc = (u32_at(b, 32) as usize).min(MAX_ARGS);
                let argv = (0..argc).map(|i| cstr(&b[296 + i * ARG_LEN..296 + (i + 1) * ARG_LEN])).collect();
                Some(Record::Exec {
                    hdr,
                    comm: cstr(&b[16..16 + COMM_LEN]),
                    filename: cstr(&b[40..40 + PATH_LEN]),
                    argv,
                    truncated: u32_at(b, 36) != 0,
                })
            }
            REC_OPEN if b.len() >= OPEN_SIZE => Some(Record::Open {
                hdr,
                dfd: u32_at(b, 16) as i32,
                flags: u32_at(b, 20),
                path: cstr(&b[24..24 + PATH_LEN]),
            }),
            REC_CONNECT if b.len() >= CONNECT_SIZE => {
                let family = u16::from_ne_bytes([b[16], b[17]]);
                let port = u16::from_be_bytes([b[18], b[19]]);
                let addr = match family {
                    AF_INET => IpAddr::V4(Ipv4Addr::new(b[24], b[25], b[26], b[27])),
                    AF_INET6 => {
                        let raw: [u8; 16] = b[24..40].try_into().ok()?;
                        let v6 = Ipv6Addr::from(raw);
                        v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
                    }
                    _ => return None,
                };
                Some(Record::Connect { hdr, addr, port })
            }
            REC_EXIT => Some(Record::Exit { hdr }),
            _ => None,
        }
    }
}

/// Feeds decoded records into a [`Tracker`], filling in what the kernel
/// side does not capture from `/proc` (with fallbacks for processes that
/// already exited).
#[derive(Debug)]
pub struct Handler {
    pub tracker: Tracker,
    proc_root: PathBuf,
    /// Processes newly attributed to an agent tree; the backend adds them to
    /// the kernel's watch set so their opens and connects are reported.
    pub to_watch: Vec<u32>,
}

impl Handler {
    pub fn new(tracker: Tracker, proc_root: &Path) -> Self {
        Self { tracker, proc_root: proc_root.to_path_buf(), to_watch: Vec::new() }
    }

    /// Learn every running process (no events) and return the pids that
    /// belong to agent trees.
    pub fn learn_existing(&mut self) -> Vec<u32> {
        let mut procs: Vec<ProcInfo> =
            list_pids(&self.proc_root).into_iter().filter_map(|pid| read_proc(&self.proc_root, pid)).collect();
        // Parents before children so attribution can walk up the tree.
        procs.sort_by_key(|p| p.pid);
        let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
        for p in procs {
            let _ = self.tracker.on_exec(p);
        }
        pids.into_iter().filter(|&pid| self.tracker.agent_root(pid).is_some()).collect()
    }

    /// Drop processes whose exit was not seen (for example when the ring
    /// buffer overflowed).
    pub fn gc(&mut self) {
        let gone: Vec<u32> =
            self.tracker.known_pids().copied().filter(|pid| !self.proc_root.join(pid.to_string()).exists()).collect();
        for pid in gone {
            self.tracker.on_exit(pid);
        }
    }

    /// Apply one record; returns the event it produced, if any.
    pub fn handle(&mut self, rec: Record) -> Option<Event> {
        match rec {
            Record::Exec { hdr, comm, filename, argv, truncated } => {
                let base = self.proc_root.join(hdr.pid.to_string());
                let ppid = if hdr.ppid != 0 {
                    hdr.ppid
                } else {
                    read_proc(&self.proc_root, hdr.pid).map(|p| p.ppid).unwrap_or(0)
                };
                if ppid != 0 {
                    self.ensure_known(ppid);
                }
                // The record is a snapshot taken at exec time. The executable
                // is reported as the path that was executed (not the symlink
                // target, so `python3` stays `python3`); /proc only fills in
                // fexecve-style execs without a path and argv beyond what the
                // kernel side captured.
                let exe = if filename.is_empty() {
                    std::fs::read_link(base.join("exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default()
                } else {
                    self.resolve(hdr.pid, AT_FDCWD, &filename)
                };
                let mut argv = argv;
                if truncated
                    && let Some(full) = read_proc(&self.proc_root, hdr.pid).map(|p| p.argv)
                    && full.first() == argv.first()
                {
                    argv = full;
                }
                let info = ProcInfo { pid: hdr.pid, ppid, uid: hdr.uid, comm, exe, argv };
                let ev = self.tracker.on_exec(info);
                if self.tracker.agent_root(hdr.pid).is_some() {
                    self.to_watch.push(hdr.pid);
                }
                ev
            }
            Record::Open { hdr, dfd, flags, path } => {
                self.ensure_known(hdr.pid);
                let path = self.resolve(hdr.pid, dfd, &path);
                // O_WRONLY (1) or O_RDWR (2).
                self.tracker.on_open(hdr.pid, &path, flags & 0b11 != 0)
            }
            Record::Connect { hdr, addr, port } => {
                self.ensure_known(hdr.pid);
                self.tracker.on_connect(hdr.pid, &addr.to_string(), port, None)
            }
            Record::Exit { hdr } => {
                self.tracker.on_exit(hdr.pid);
                None
            }
        }
    }

    /// Make sure `pid` and its ancestors are known to the tracker, reading
    /// them from /proc (forked children that never exec'd are not
    /// reported by the kernel side).
    fn ensure_known(&mut self, pid: u32) {
        let mut cur = pid;
        for _ in 0..64 {
            if cur == 0 || self.tracker.knows(cur) {
                return;
            }
            let Some(p) = read_proc(&self.proc_root, cur) else { return };
            let parent = p.ppid;
            let _ = self.tracker.on_exec(p);
            cur = parent;
        }
    }

    /// Absolute form of `path` as seen by `pid` (relative paths are
    /// resolved against its cwd or the directory fd `dfd`). Returns the
    /// path unchanged when the base cannot be read.
    fn resolve(&self, pid: u32, dfd: i32, path: &str) -> String {
        if path.starts_with('/') {
            return normalize(Path::new(path));
        }
        let base = self.proc_root.join(pid.to_string());
        let link = if dfd == AT_FDCWD { base.join("cwd") } else { base.join("fd").join(dfd.to_string()) };
        match std::fs::read_link(link) {
            Ok(dir) if dir.is_absolute() => normalize(&dir.join(path)),
            _ => path.to_string(),
        }
    }
}

/// Lexically remove `.` and `..` components (no symlink resolution).
fn normalize(path: &Path) -> String {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nandi_core::EventKind;
    use nandi_core::config::SensorConfig;

    fn hdr_bytes(kind: u32, pid: u32, ppid: u32, size: usize) -> Vec<u8> {
        let mut b = vec![0u8; size];
        b[0..4].copy_from_slice(&kind.to_ne_bytes());
        b[4..8].copy_from_slice(&pid.to_ne_bytes());
        b[8..12].copy_from_slice(&ppid.to_ne_bytes());
        b[12..16].copy_from_slice(&1000u32.to_ne_bytes());
        b
    }

    fn put(b: &mut [u8], off: usize, s: &str) {
        b[off..off + s.len()].copy_from_slice(s.as_bytes());
    }

    fn exec_bytes(pid: u32, ppid: u32, comm: &str, filename: &str, argv: &[&str]) -> Vec<u8> {
        let mut b = hdr_bytes(REC_EXEC, pid, ppid, EXEC_SIZE);
        put(&mut b, 16, comm);
        b[32..36].copy_from_slice(&(argv.len() as u32).to_ne_bytes());
        put(&mut b, 40, filename);
        for (i, a) in argv.iter().enumerate() {
            put(&mut b, 296 + i * ARG_LEN, a);
        }
        b
    }

    fn open_bytes(pid: u32, dfd: i32, flags: u32, path: &str) -> Vec<u8> {
        let mut b = hdr_bytes(REC_OPEN, pid, 0, OPEN_SIZE);
        b[16..20].copy_from_slice(&dfd.to_ne_bytes());
        b[20..24].copy_from_slice(&flags.to_ne_bytes());
        put(&mut b, 24, path);
        b
    }

    #[test]
    fn decodes_records() {
        let rec = Record::parse(&exec_bytes(7, 3, "curl", "/usr/bin/curl", &["curl", "-s", "x.example"])).unwrap();
        assert_eq!(
            rec,
            Record::Exec {
                hdr: Header { pid: 7, ppid: 3, uid: 1000 },
                comm: "curl".into(),
                filename: "/usr/bin/curl".into(),
                argv: vec!["curl".into(), "-s".into(), "x.example".into()],
                truncated: false,
            }
        );
        let rec = Record::parse(&open_bytes(7, AT_FDCWD, 0o1101, "notes/.env")).unwrap();
        assert!(matches!(rec, Record::Open { dfd: AT_FDCWD, flags: 0o1101, ref path, .. } if path == "notes/.env"));

        let mut c = hdr_bytes(REC_CONNECT, 7, 0, CONNECT_SIZE);
        c[16..18].copy_from_slice(&AF_INET.to_ne_bytes());
        c[18..20].copy_from_slice(&443u16.to_be_bytes());
        c[24..28].copy_from_slice(&[10, 1, 2, 3]);
        assert!(
            matches!(Record::parse(&c), Some(Record::Connect { port: 443, addr, .. }) if addr.to_string() == "10.1.2.3")
        );
        // IPv4-mapped IPv6 is reported as IPv4.
        c[16..18].copy_from_slice(&AF_INET6.to_ne_bytes());
        c[24..40].copy_from_slice(&Ipv4Addr::new(10, 9, 8, 7).to_ipv6_mapped().octets());
        assert!(matches!(Record::parse(&c), Some(Record::Connect { addr, .. }) if addr.to_string() == "10.9.8.7"));

        assert!(matches!(Record::parse(&hdr_bytes(REC_EXIT, 7, 0, 16)), Some(Record::Exit { .. })));
        assert_eq!(Record::parse(&hdr_bytes(REC_EXEC, 7, 0, 64)), None, "short record");
        assert_eq!(Record::parse(&hdr_bytes(99, 7, 0, 64)), None, "unknown type");
        assert_eq!(Record::parse(&[1, 0, 0]), None);
    }

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize(Path::new("/home/u/proj/../.aws/./credentials")), "/home/u/.aws/credentials");
        assert_eq!(normalize(Path::new("/../etc/shadow")), "/etc/shadow");
    }

    fn handler() -> Handler {
        // An empty proc root: every /proc lookup falls back, as it does for
        // processes that already exited.
        let root = std::env::temp_dir().join("nandi-records-empty-proc");
        let cfg = SensorConfig { enabled: true, ..SensorConfig::default() };
        Handler::new(Tracker::new(cfg), &root)
    }

    #[test]
    fn short_lived_processes_are_attributed_from_records_alone() {
        let mut h = handler();
        let rec = |b: Vec<u8>| Record::parse(&b).unwrap();
        assert!(h.handle(rec(exec_bytes(100, 1, "node", "/usr/bin/node", &["node", "/opt/bin/claude"]))).is_none());
        assert_eq!(h.to_watch, vec![100], "the agent root is watched");
        let ev =
            h.handle(rec(exec_bytes(101, 100, "cat", "/usr/bin/cat", &["cat", "/home/u/.ssh/id_ed25519"]))).unwrap();
        assert_eq!(ev.agent, "claude");
        assert!(matches!(ev.kind, EventKind::Process(ref p) if p.filename == "/usr/bin/cat" && p.ppid == 100));
        let ev = h.handle(rec(open_bytes(101, AT_FDCWD, 0, "/home/u/.ssh/id_ed25519"))).unwrap();
        assert!(matches!(ev.kind, EventKind::File(ref f) if !f.write && f.comm == "cat"));
        // Writes are flagged; unresolvable relative paths stay relative.
        let ev = h.handle(rec(open_bytes(101, AT_FDCWD, 0o101, "/home/u/.aws/credentials"))).unwrap();
        assert!(matches!(ev.kind, EventKind::File(ref f) if f.write));
        assert!(h.handle(rec(open_bytes(101, AT_FDCWD, 0, "src/main.rs"))).is_none());
        assert!(h.handle(Record::Exit { hdr: Header { pid: 101, ppid: 0, uid: 0 } }).is_none());
        assert!(!h.tracker.knows(101));
        // Unrelated processes produce nothing and are not watched.
        assert!(h.handle(rec(exec_bytes(200, 1, "vim", "/usr/bin/vim", &["vim"]))).is_none());
        assert_eq!(h.to_watch, vec![100, 101]);
    }

    #[test]
    fn enriches_from_live_proc() {
        // This test process is alive, so relative paths resolve against its
        // cwd and unknown parents are read from /proc.
        let mut h = Handler::new(Tracker::new(SensorConfig::default()), Path::new("/proc"));
        let me = std::process::id();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(h.resolve(me, AT_FDCWD, "a/../b.txt"), cwd.join("b.txt").to_string_lossy());
        assert_eq!(h.resolve(me, AT_FDCWD, "/etc/./hosts"), "/etc/hosts");
        h.ensure_known(me);
        assert!(h.tracker.knows(me));
        assert!(!h.learn_existing().contains(&me));
    }
}
