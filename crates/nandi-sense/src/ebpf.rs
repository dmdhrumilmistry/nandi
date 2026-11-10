//! eBPF backend (Linux, cargo feature `ebpf`).
//!
//! Loads `bpf/sense.bpf.c` (compiled by `build.rs`), attaches its
//! tracepoints and reads fixed-size records from a ring buffer. Execs and
//! exits are reported for every process so attribution works like in the
//! procfs backend; opens and connects are reported by the kernel only for
//! processes in the `watched` map. This module keeps that map in sync with
//! the tracker's agent trees, and the kernel adds children forked by a
//! watched process on its own, so even processes that live for a few
//! microseconds are seen.
//!
//! Needs root (or CAP_BPF + CAP_PERFMON) and kernel 5.8+ (ring buffer).

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use aya::Ebpf;
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::{RawTracePoint, TracePoint};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use nandi_core::Event;
use nandi_core::config::SensorConfig;

use crate::Tracker;
use crate::records::{Handler, Record};

/// The compiled BPF object.
fn object() -> &'static [u8] {
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sense.bpf.o"))
}

/// Tracepoint programs: (program, category, tracepoint).
const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("handle_newtask", "task", "task_newtask"),
    ("handle_exec", "sched", "sched_process_exec"),
    ("handle_exit", "sched", "sched_process_exit"),
];

/// Raw tracepoint programs: (program, tracepoint). `sys_enter` covers
/// execve, execveat, openat, openat2, open and connect.
const RAW_TRACEPOINTS: &[(&str, &str)] = &[("handle_sys_enter", "sys_enter")];

/// Index of the own tgid in the `config` map (see the C source).
const CFG_OWN_TGID: u32 = 0;
/// Indexes of the `stats` counters (see the C source).
const STAT_EXEC_ENTER: u32 = 0;
const STAT_EXEC_EMIT: u32 = 1;
const STAT_DROPPED: u32 = 2;
const STAT_EXEC_SEEN: u32 = 3;
const STAT_EXEC_ENTER_FAIL: u32 = 4;

const TICK: Duration = Duration::from_secs(1);
const RESOLVE_EVERY: u32 = 300; // ticks (5 minutes)
const GC_EVERY: u32 = 30; // ticks

/// A loaded and attached eBPF sensor. Dropping it detaches the programs.
pub struct Sensor {
    // Owns the programs and their links.
    _bpf: Ebpf,
    ring: RingBuf<MapData>,
    watched: HashMap<MapData, u32, u8>,
    stats: Array<MapData, u64>,
}

impl std::fmt::Debug for Sensor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sensor").finish_non_exhaustive()
    }
}

/// Whether the eBPF backend can be loaded here (privileges, kernel
/// support). Loads and immediately unloads the programs.
pub fn available() -> bool {
    Sensor::load().is_ok()
}

/// Load the eBPF backend and run it until `shutdown` resolves, sending
/// events to `tx`.
pub async fn run(
    cfg: SensorConfig,
    tx: mpsc::Sender<Event>,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    Sensor::load()?.run(cfg, tx, shutdown).await
}

impl Sensor {
    /// Load the BPF object and attach its tracepoints. Fails with a
    /// descriptive error when privileges or kernel support are missing.
    pub fn load() -> anyhow::Result<Self> {
        raise_memlock_limit();
        let mut bpf = Ebpf::load(object()).map_err(|e| {
            anyhow::Error::new(e).context("loading the eBPF sensor (needs root or CAP_BPF + CAP_PERFMON, kernel 5.8+)")
        })?;
        {
            let mut config: Array<_, u32> =
                Array::try_from(bpf.map_mut("config").context("BPF map `config` missing")?)?;
            config.set(CFG_OWN_TGID, &std::process::id(), 0).context("writing the BPF config map")?;
        }
        for &(name, category, tracepoint) in TRACEPOINTS {
            let prog: &mut TracePoint = bpf
                .program_mut(name)
                .with_context(|| format!("BPF program `{name}` missing"))?
                .try_into()
                .with_context(|| format!("BPF program `{name}` is not a tracepoint"))?;
            prog.load().with_context(|| format!("loading BPF program `{name}`"))?;
            prog.attach(category, tracepoint).with_context(|| format!("attaching {category}/{tracepoint}"))?;
        }
        for &(name, tracepoint) in RAW_TRACEPOINTS {
            let prog: &mut RawTracePoint = bpf
                .program_mut(name)
                .with_context(|| format!("BPF program `{name}` missing"))?
                .try_into()
                .with_context(|| format!("BPF program `{name}` is not a raw tracepoint"))?;
            prog.load().with_context(|| format!("loading BPF program `{name}`"))?;
            prog.attach(tracepoint).with_context(|| format!("attaching raw tracepoint {tracepoint}"))?;
        }
        let ring = RingBuf::try_from(bpf.take_map("events").context("BPF map `events` missing")?)?;
        let watched = HashMap::try_from(bpf.take_map("watched").context("BPF map `watched` missing")?)?;
        let stats = Array::try_from(bpf.take_map("stats").context("BPF map `stats` missing")?)?;
        Ok(Self { _bpf: bpf, ring, watched, stats })
    }

    /// Read records until `shutdown` resolves, sending events to `tx`.
    pub async fn run(
        self,
        cfg: SensorConfig,
        tx: mpsc::Sender<Event>,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<()> {
        let Sensor { _bpf, ring, mut watched, stats } = self;
        let mut dropped = 0;
        let hosts = cfg.llm_hosts.clone();
        let mut handler = Handler::new(Tracker::new(cfg), Path::new("/proc"));
        // Programs are attached, so processes started from here on are
        // reported; learn the ones that already run.
        let existing = handler.learn_existing();
        tracing::debug!(agents = existing.len(), "eBPF sensor learned running processes");
        for pid in existing {
            watch(&mut watched, pid);
        }
        // SAFETY: the ring buffer owns its map fd, which stays open until the
        // AsyncFd (and with it the ring buffer) is dropped at the end of this
        // function; the inner value is never taken out.
        let mut ring = unsafe { AsyncFd::register_with_interest(ring, Interest::READABLE) }
            .map_err(std::io::Error::from)
            .context("polling the BPF ring buffer")?;
        let mut tick = tokio::time::interval(TICK);
        let mut ticks: u32 = 0;
        let mut records: Vec<Record> = Vec::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::debug!(
                        exec_enter = stat(&stats, STAT_EXEC_ENTER),
                        exec_enter_fail = stat(&stats, STAT_EXEC_ENTER_FAIL),
                        exec_seen = stat(&stats, STAT_EXEC_SEEN),
                        exec_emit = stat(&stats, STAT_EXEC_EMIT),
                        dropped = stat(&stats, STAT_DROPPED),
                        "eBPF sensor stopped"
                    );
                    return Ok(());
                }
                guard = ring.readable_mut() => {
                    let mut guard = guard.context("polling the BPF ring buffer")?;
                    drain(guard.get_inner_mut(), &mut records);
                    guard.clear_ready();
                }
                _ = tick.tick() => {
                    // Also drain here so a missed wakeup cannot stall records.
                    drain(ring.get_mut(), &mut records);
                    let now = stat(&stats, STAT_DROPPED);
                    if now > dropped {
                        tracing::warn!("eBPF ring buffer full: {} records dropped", now - dropped);
                        dropped = now;
                    }
                    if ticks.is_multiple_of(RESOLVE_EVERY) {
                        crate::resolve_hosts(&mut handler.tracker, &hosts).await;
                    }
                    if ticks % GC_EVERY == GC_EVERY - 1 {
                        handler.gc();
                    }
                    ticks = ticks.wrapping_add(1);
                }
            }
            for rec in records.drain(..) {
                tracing::trace!(?rec, "eBPF record");
                let ev = handler.handle(rec);
                for pid in handler.to_watch.drain(..) {
                    watch(&mut watched, pid);
                }
                if let Some(ev) = ev
                    && tx.send(ev).await.is_err()
                {
                    return Ok(());
                }
            }
        }
    }
}

fn drain(ring: &mut RingBuf<MapData>, out: &mut Vec<Record>) {
    while let Some(item) = ring.next() {
        if let Some(rec) = Record::parse(&item) {
            out.push(rec);
        }
    }
}

fn stat(stats: &Array<MapData, u64>, index: u32) -> u64 {
    stats.get(&index, 0).unwrap_or(0)
}

fn watch(watched: &mut HashMap<MapData, u32, u8>, pid: u32) {
    if let Err(e) = watched.insert(&pid, &1, 0) {
        tracing::debug!(pid, "could not watch process: {e}");
    }
}

/// Kernels before 5.11 charge BPF maps against RLIMIT_MEMLOCK; lift it.
fn raise_memlock_limit() {
    let rlim = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    // SAFETY: setrlimit only reads the struct passed by reference.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        tracing::debug!("could not raise RLIMIT_MEMLOCK: {}", std::io::Error::last_os_error());
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::time::Instant;

    use nandi_core::EventKind;

    use super::*;

    /// Needs root (or CAP_BPF + CAP_PERFMON); run with
    /// `sudo -E cargo test -p nandi-sense --features ebpf -- --ignored ebpf_`.
    #[tokio::test]
    #[ignore = "needs root and a kernel with eBPF ring buffers"]
    async fn ebpf_reports_short_lived_children_of_an_agent() {
        let dir = std::env::temp_dir().join(format!("nandi-ebpf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret = dir.join("fake.env");
        std::fs::write(&secret, "X=1").unwrap();
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // A non-loopback address of this host (loopback is ignored by the
        // tracker); connecting to it reaches the listener above.
        let host_ip = std::process::Command::new("hostname")
            .arg("-I")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.split_whitespace().find(|a| !a.contains(':') && !a.starts_with("127.")).map(String::from));

        let cfg = SensorConfig {
            enabled: true,
            agent_comms: vec!["nandi-fake-agent".into()],
            sensitive_paths: vec!["*/fake.env".into()],
            llm_hosts: Vec::new(),
            ..SensorConfig::default()
        };
        let _ = tracing_subscriber::fmt().with_env_filter("nandi_sense=trace").with_test_writer().try_init();
        let sensor = Sensor::load().expect("loading the eBPF sensor");
        let (tx, mut rx) = mpsc::channel(1024);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(sensor.run(cfg, tx, async move {
            let _ = stop_rx.await;
        }));
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The "agent" is a shell whose argv[0] matches agent_comms. Every
        // child below lives for a few milliseconds at most.
        let connect = match &host_ip {
            Some(ip) => format!("curl -s -m 1 http://{ip}:{port}/ >/dev/null || true"),
            None => String::new(),
        };
        let script = format!("sleep 0.3; cat '{}' >/dev/null; true; /bin/true; {connect}", secret.display());
        let mut agent =
            std::process::Command::new("bash").arg0("nandi-fake-agent").arg("-c").arg(&script).spawn().unwrap();
        // Poll without blocking the runtime the sensor runs on.
        let status = loop {
            if let Some(status) = agent.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(status.success());

        let mut events: Vec<Event> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let done = |events: &[Event]| {
            let exec = |name: &str| {
                events.iter().any(|e| matches!(&e.kind, EventKind::Process(p) if p.filename.ends_with(name)))
            };
            let file = events.iter().any(|e| matches!(&e.kind, EventKind::File(f) if f.path.ends_with("fake.env")));
            let net =
                host_ip.is_none() || events.iter().any(|e| matches!(&e.kind, EventKind::Network(n) if n.dport == port));
            exec("/cat") && exec("/true") && file && net
        };
        while !done(&events) && Instant::now() < deadline {
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                println!("event: {ev:?}");
                events.push(ev);
            }
        }
        if task.is_finished() {
            panic!("sensor stopped early: {:?}", task.await);
        }
        let _ = stop_tx.send(());
        task.await.unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        drop(listener);
        assert!(done(&events), "missing events (host ip {host_ip:?}): {events:#?}");
        assert!(events.iter().all(|e| e.agent == "nandi-fake-agent"), "{events:#?}");
    }
}
