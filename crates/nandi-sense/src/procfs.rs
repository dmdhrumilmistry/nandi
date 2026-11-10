//! `/proc` polling backend (Linux).
//!
//! Every tick it diffs the process list, then for processes in agent trees
//! inspects open file descriptors (sensitive files, sockets) and maps socket
//! inodes to TCP connections from `/proc/net/tcp{,6}`. Cheap enough to run
//! every 500 ms, but short-lived processes and files opened and closed
//! between ticks are missed; the eBPF backend does not have that gap.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;

use tokio::sync::mpsc;

use nandi_core::Event;
use nandi_core::config::SensorConfig;

use crate::{ProcInfo, Tracker};

const TICK: Duration = Duration::from_millis(500);
const RESOLVE_EVERY: u32 = 600; // ticks (5 minutes)

/// Poll `/proc` until `shutdown` resolves, sending events to `tx`.
pub async fn run(
    cfg: SensorConfig,
    tx: mpsc::Sender<Event>,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    run_at(Path::new("/proc"), cfg, tx, shutdown).await
}

/// As [`run`] with a custom proc root (tests).
pub async fn run_at(
    root: &Path,
    cfg: SensorConfig,
    tx: mpsc::Sender<Event>,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    anyhow::ensure!(root.join("self").exists() || root != Path::new("/proc"), "/proc is not available");
    let hosts = cfg.llm_hosts.clone();
    let mut tracker = Tracker::new(cfg);
    let mut known: HashSet<u32> = HashSet::new();
    let mut first = true;
    let mut tick: u32 = 0;
    tokio::pin!(shutdown);
    loop {
        if tick.is_multiple_of(RESOLVE_EVERY) {
            crate::resolve_hosts(&mut tracker, &hosts).await;
        }
        tick = tick.wrapping_add(1);
        for ev in scan(root, &mut tracker, &mut known, first) {
            if tx.send(ev).await.is_err() {
                return Ok(());
            }
        }
        first = false;
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = tokio::time::sleep(TICK) => {}
        }
    }
}

/// One polling pass. On the first pass existing processes are learned
/// without emitting exec events.
pub fn scan(root: &Path, tracker: &mut Tracker, known: &mut HashSet<u32>, first: bool) -> Vec<Event> {
    let mut out = Vec::new();
    let pids = list_pids(root);
    let current: HashSet<u32> = pids.iter().copied().collect();
    for gone in known.difference(&current).copied().collect::<Vec<_>>() {
        tracker.on_exit(gone);
        known.remove(&gone);
    }
    // Parents before children so attribution can walk up the tree.
    let mut fresh: Vec<ProcInfo> =
        pids.iter().filter(|p| !known.contains(p)).filter_map(|&pid| read_proc(root, pid)).collect();
    fresh.sort_by_key(|p| p.pid);
    for p in fresh {
        known.insert(p.pid);
        let ev = tracker.on_exec(p);
        if !first && let Some(ev) = ev {
            out.push(ev);
        }
    }

    let agent_pids: Vec<u32> = pids.iter().copied().filter(|&pid| tracker.agent_root(pid).is_some()).collect();
    if agent_pids.is_empty() {
        return out;
    }
    let tcp = read_tcp(root);
    for pid in agent_pids {
        for (target, write) in open_fds(root, pid) {
            if let Some(inode) = target.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                if let Some((addr, port)) = inode.parse::<u64>().ok().and_then(|i| tcp.get(&i))
                    && let Some(ev) = tracker.on_connect(pid, addr, *port, None)
                {
                    out.push(ev);
                }
            } else if target.starts_with('/')
                && let Some(ev) = tracker.on_open(pid, &target, write)
            {
                out.push(ev);
            }
        }
    }
    out
}

pub(crate) fn list_pids(root: &Path) -> Vec<u32> {
    let Ok(dir) = fs::read_dir(root) else { return Vec::new() };
    dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect()
}

/// Read pid, ppid, comm, uid, exe and argv of one process.
pub fn read_proc(root: &Path, pid: u32) -> Option<ProcInfo> {
    let base = root.join(pid.to_string());
    let stat = fs::read_to_string(base.join("stat")).ok()?;
    let (comm, rest) = parse_stat(&stat)?;
    let ppid = rest.split_whitespace().nth(1)?.parse().ok()?;
    let uid = fs::read_to_string(base.join("status"))
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).and_then(|l| l.split_whitespace().nth(1)?.parse().ok()))
        .unwrap_or(0);
    let exe = fs::read_link(base.join("exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let argv = fs::read(base.join("cmdline"))
        .map(|b| {
            b.split(|&c| c == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect()
        })
        .unwrap_or_default();
    Some(ProcInfo { pid, ppid, uid, comm, exe, argv })
}

/// Split `/proc/<pid>/stat` into comm and the fields after it. comm may
/// contain spaces and parentheses, so the last `)` ends it.
fn parse_stat(stat: &str) -> Option<(String, &str)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    Some((stat[open + 1..close].to_string(), stat.get(close + 1..)?.trim_start()))
}

/// Targets of open file descriptors with a write flag from fdinfo.
fn open_fds(root: &Path, pid: u32) -> Vec<(String, bool)> {
    let base = root.join(pid.to_string());
    let Ok(dir) = fs::read_dir(base.join("fd")) else { return Vec::new() };
    let mut out = Vec::new();
    for entry in dir.flatten().take(4096) {
        let Ok(target) = fs::read_link(entry.path()) else { continue };
        let target = target.to_string_lossy().into_owned();
        let write = fs::read_to_string(base.join("fdinfo").join(entry.file_name()))
            .ok()
            .and_then(|s| {
                s.lines().find(|l| l.starts_with("flags:")).and_then(|l| u32::from_str_radix(l[6..].trim(), 8).ok())
            })
            .is_some_and(|flags| flags & 0b11 != 0);
        out.push((target, write));
    }
    out
}

/// socket inode -> (remote address, remote port) for connected TCP sockets.
fn read_tcp(root: &Path) -> HashMap<u64, (String, u16)> {
    let mut map = HashMap::new();
    for (file, v6) in [("net/tcp", false), ("net/tcp6", true)] {
        let Ok(text) = fs::read_to_string(root.join(file)) else { continue };
        for line in text.lines().skip(1) {
            if let Some((inode, addr, port)) = parse_tcp_line(line, v6) {
                map.insert(inode, (addr, port));
            }
        }
    }
    map
}

/// Parse one `/proc/net/tcp` line; keeps ESTABLISHED (01) and SYN_SENT (02).
fn parse_tcp_line(line: &str, v6: bool) -> Option<(u64, String, u16)> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 10 || !matches!(cols[3], "01" | "02") {
        return None;
    }
    let (addr_hex, port_hex) = cols[2].split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let inode = cols[9].parse().ok()?;
    let addr = if v6 {
        if addr_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for word in 0..4 {
            let w = u32::from_str_radix(&addr_hex[word * 8..word * 8 + 8], 16).ok()?;
            bytes[word * 4..word * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        let ip = Ipv6Addr::from(bytes);
        match ip.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => ip.to_string(),
        }
    } else {
        Ipv4Addr::from(u32::from_str_radix(addr_hex, 16).ok()?.to_le_bytes()).to_string()
    };
    Some((inode, addr, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_odd_comm() {
        let (comm, rest) = parse_stat("1234 (my (weird) proc) S 99 1234 1234 0 -1").unwrap();
        assert_eq!(comm, "my (weird) proc");
        assert_eq!(rest.split_whitespace().nth(1), Some("99"));
    }

    #[test]
    fn parses_tcp_lines() {
        let v4 = "   1: 0100007F:1F90 0100A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 424242 1";
        assert_eq!(parse_tcp_line(v4, false), Some((424242, "192.168.0.1".into(), 443)));
        let listen = "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1";
        assert_eq!(parse_tcp_line(listen, false), None);
        let v6 = "  2: 00000000000000000000000001000000:9C40 0000000000000000FFFF00000100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 777 1";
        assert_eq!(parse_tcp_line(v6, true), Some((777, "127.0.0.1".into(), 80)));
    }

    #[test]
    fn reads_own_process() {
        let me = read_proc(Path::new("/proc"), std::process::id()).unwrap();
        assert!(!me.comm.is_empty());
        assert!(!me.argv.is_empty());
    }

    #[test]
    fn live_scan_sees_child_of_fake_agent() {
        // Pretend this test binary is an agent, spawn a child that holds a
        // "sensitive" file open, and check both events are produced.
        let dir = std::env::temp_dir().join(format!("nandi-sense-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("fake.env");
        std::fs::write(&secret, "X=1").unwrap();
        let me = read_proc(Path::new("/proc"), std::process::id()).unwrap();
        let cfg = SensorConfig {
            enabled: true,
            agent_comms: vec![me.comm.clone()],
            sensitive_paths: vec!["*/fake.env".into()],
            ..SensorConfig::default()
        };
        let mut tracker = Tracker::new(cfg);
        // The tracker ignores its own pid as a root, so use a child shell
        // as the "agent" and its child as the observed process.
        tracker.own_pid = 0;
        let mut known = HashSet::new();
        scan(Path::new("/proc"), &mut tracker, &mut known, true);
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("exec 3<'{}'; sleep 3", secret.display()))
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let events = scan(Path::new("/proc"), &mut tracker, &mut known, false);
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(events.iter().any(|e| e.kind_name() == "process"), "{events:?}");
        assert!(events.iter().any(|e| e.kind_name() == "file"), "{events:?}");
    }
}
