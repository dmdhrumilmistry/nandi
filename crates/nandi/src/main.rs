//! The `nandi` command line: gateway, stdio wrapper, hook client, policy
//! tooling, audit tooling and admin client.

mod discover;
mod init;
mod offline;
mod packs;
mod remote;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::sync::watch;

use nandi_core::Config;
use nandi_core::config::{FailMode, MlConfig};
use nandi_engine::Classifier;
use nandi_gateway::hook::HookFormat;
use nandi_gateway::stdio::WrapOptions;
use nandi_gateway::{App, admin, hook, proxy, stdio};

use remote::{AdminOpts, ApprovalsCmd, PinsCmd, Remote};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Parser)]
#[command(name = "nandi", version, about = "Zero-trust gateway and runtime monitor for AI agents")]
struct Cli {
    /// Configuration file.
    #[arg(short, long, global = true, default_value = "nandi.yaml", env = "NANDI_CONFIG")]
    config: PathBuf,
    /// Log filter (error, warn, info, debug, trace or a tracing directive).
    #[arg(long, global = true, default_value = "info", env = "NANDI_LOG")]
    log_level: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the gateway and the admin API.
    Run,
    /// Interpose on a stdio MCP server: `nandi wrap --server NAME -- CMD ARGS...`.
    Wrap {
        /// Logical server name used in policies (`server/tool`).
        #[arg(long)]
        server: String,
        /// Agent identity to attribute the traffic to.
        #[arg(long, env = "NANDI_AGENT", default_value = "local")]
        agent: String,
        /// Session id (default: one per wrapper process).
        #[arg(long)]
        session: Option<String>,
        /// The MCP server command and its arguments.
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// Coding-agent hook: read the payload on stdin, ask nandi, print the answer.
    Hook {
        /// claude-code | cursor | generic
        format: String,
        #[arg(long, value_name = "URL")]
        admin: Option<String>,
        #[arg(long, env = "NANDI_ADMIN_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Allow the action when nandi is unreachable (default: block).
        #[arg(long)]
        fail_open: bool,
    },
    /// Validate and test policies.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Re-evaluate recorded events with the current config and policy and
    /// show the verdicts that would change.
    Replay {
        /// Audit database (default: from the config).
        #[arg(long)]
        db: Option<PathBuf>,
        /// Audit signing key (default: from the config).
        #[arg(long)]
        key: Option<PathBuf>,
        /// Start after this sequence number.
        #[arg(long, default_value_t = 0)]
        since_seq: u64,
        /// Maximum number of events to replay (0 = all).
        #[arg(long, default_value_t = 0)]
        limit: usize,
        /// JSON lines output.
        #[arg(long)]
        json: bool,
    },
    /// Verify, export and inspect the signed audit log.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// Agent API keys.
    Key {
        #[command(subcommand)]
        cmd: KeyCmd,
    },
    /// Biscuit delegation tokens.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Gateway status (admin API).
    Status {
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Active sessions (admin API).
    Sessions {
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Pending approvals (admin API).
    Approvals {
        #[command(subcommand)]
        cmd: Option<ApprovalsCmd>,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Deny every action of an agent until revived (admin API).
    Kill {
        agent: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Lift the kill switch for an agent (admin API).
    Revive {
        agent: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Tool definition pins (admin API).
    Pins {
        #[command(subcommand)]
        cmd: Option<PinsCmd>,
        /// A2A Agent Card pins instead of tool pins.
        #[arg(long)]
        cards: bool,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// MCP servers with their package, approval, pinning and risk (admin API).
    Servers {
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Stream live events (admin API).
    Tail {
        #[arg(long)]
        agent: Option<String>,
        /// allow | alert | redact | ask | deny
        #[arg(long)]
        min_verdict: Option<String>,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// Inventory the AI agents, MCP servers, hooks, skills and plugins on
    /// this machine and show which of them bypass nandi.
    Discover {
        /// Home directory to scan (default: $HOME).
        #[arg(long, value_name = "DIR")]
        home: Option<PathBuf>,
        /// Project directory to scan; repeatable (default: the current directory).
        #[arg(long = "project", value_name = "DIR")]
        projects: Vec<PathBuf>,
        /// Print the inventory as JSON.
        #[arg(long)]
        json: bool,
        /// Print the configuration changes that bring everything under nandi.
        #[arg(long)]
        suggest: bool,
        /// nandi config path used in suggested commands (default: --config, made absolute).
        #[arg(long, value_name = "PATH")]
        nandi_config: Option<PathBuf>,
        /// nandi proxy base URL; repeatable (default: http://127.0.0.1:8787 and
        /// http://localhost:8787, plus `listen.proxy` from the config).
        #[arg(long = "proxy-url", value_name = "URL")]
        proxy_urls: Vec<String>,
        /// Send the inventory to the admin API (`POST /v1/inventory`) for the dashboard.
        #[arg(long)]
        report: bool,
        /// Admin API base URL (default: `admin.listen` from the config, else
        /// http://127.0.0.1:8788).
        #[arg(long, value_name = "URL")]
        admin: Option<String>,
        /// Admin bearer token (default: `admin.token` from the config).
        #[arg(long, env = "NANDI_ADMIN_TOKEN", hide_env_values = true)]
        token: Option<String>,
    },
    /// Write a starter nandi.yaml and policies.
    Init {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
    },
    /// Run the attack / false-positive evaluation corpus against the
    /// current engine (`eval/scenarios` in the repository).
    Eval {
        /// Directory of scenario YAML files.
        #[arg(long, default_value = "eval/scenarios")]
        dir: PathBuf,
        /// Print the full report as JSON.
        #[arg(long)]
        json: bool,
        /// Fail when the attack detection rate is below this (0.0 - 1.0).
        #[arg(long, default_value_t = 0.0)]
        min_detection: f64,
        /// Fail when the false-positive rate is above this (0.0 - 1.0).
        #[arg(long, default_value_t = 1.0)]
        max_false_positives: f64,
    },
    /// Watch agent processes on this host and print the sensor events
    /// (the same sensor `run` starts when `sensor.enabled` is set).
    Sense,
    /// Print the version.
    Version,
}

#[derive(Debug, Subcommand)]
enum PolicyCmd {
    /// Load the configured policies and print warnings.
    Validate,
    /// Evaluate events from a JSON lines file, in order, and print verdicts.
    Test {
        /// One event per line, or `{"event": ..., "groups": [...]}`.
        #[arg(long)]
        events: PathBuf,
        /// JSON lines output.
        #[arg(long)]
        json: bool,
    },
    /// List the bundled policy packs.
    Packs,
    /// Print a bundled policy pack, to save as a rule file:
    /// `nandi policy pack payments > policies/payments.yaml`.
    Pack {
        /// Pack name from `nandi policy packs`.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCmd {
    /// Check the hash chain and signatures.
    Verify {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
        /// Verify an exported JSON lines file instead (needs --pubkey).
        #[arg(long, requires = "pubkey", conflicts_with_all = ["db", "key"])]
        export: Option<PathBuf>,
        /// Hex Ed25519 public key of the log.
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Export every record as JSON lines.
    Export {
        /// Output file, `-` for stdout.
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Print the newest record's sequence number and hash.
    Head {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        key: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum KeyCmd {
    /// Generate an agent API key and its SHA-256 for `identity.api_keys`.
    Generate,
    /// SHA-256 of an existing key (`-` reads it from stdin).
    Hash { key: String },
}

#[derive(Debug, Subcommand)]
enum TokenCmd {
    /// Generate a root key pair.
    Keygen,
    /// Mint a token for an agent, scoped to tool patterns.
    Mint {
        #[arg(long, env = "NANDI_BISCUIT_PRIVATE_KEY", hide_env_values = true)]
        private_key: String,
        #[arg(long)]
        agent: String,
        /// `server/tool`, `server/*` or `*`; repeatable.
        #[arg(long = "tool", required = true)]
        tools: Vec<String>,
        /// Lifetime in seconds.
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
    },
    /// Narrow a token for delegation (no private key needed).
    Attenuate {
        #[arg(long)]
        token: String,
        #[arg(long)]
        public_key: String,
        #[arg(long = "tool", required = true)]
        tools: Vec<String>,
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Print a token's blocks and their revocation ids (signatures are not checked).
    Inspect {
        #[arg(long)]
        token: String,
    },
    /// Revoke a token block by its revocation id (admin API). Revoking a
    /// block cancels that token and every token attenuated from it.
    Revoke {
        /// Revocation id from `nandi token inspect`.
        id: String,
        #[command(flatten)]
        admin: AdminOpts,
    },
    /// List revoked token blocks (admin API).
    Revoked {
        #[command(flatten)]
        admin: AdminOpts,
    },
}

fn init_logging(filter: &str, json: bool) {
    let filter =
        tracing_subscriber::EnvFilter::try_new(filter).unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr);
    if json {
        builder.json().init();
    } else {
        builder.with_ansi(std::io::stderr().is_terminal()).init();
    }
}

/// Load the config file and return it with its directory.
fn load_config(path: &Path) -> anyhow::Result<(Config, PathBuf)> {
    let cfg = Config::load(path).map_err(|e| anyhow::anyhow!("{e} (create one with `nandi init`)"))?;
    let base = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Ok((cfg, base))
}

/// Resolves once Ctrl-C or SIGTERM is received.
async fn termination() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Build the prompt-injection classifier when `ml.enabled` is set. A model
/// that fails to load stops startup under `fail_mode: closed` and is skipped
/// with a warning under `fail_mode: open`.
fn ml_classifier(cfg: &Config, base: &Path) -> anyhow::Result<Option<Arc<dyn Classifier>>> {
    if !cfg.ml.enabled {
        return Ok(None);
    }
    if !nandi_ml::AVAILABLE {
        tracing::warn!(
            "ml.enabled is set but this nandi binary was built without the ML classifier \
             (rebuild with `cargo build -p nandi --features ml`); continuing without it"
        );
        return Ok(None);
    }
    match load_classifier(&cfg.ml, base) {
        Ok(c) => Ok(Some(Arc::new(c))),
        Err(e) if cfg.fail_mode == FailMode::Open => {
            tracing::warn!(error = %format!("{e:#}"), "ML classifier unavailable; continuing without it (fail_mode: open)");
            Ok(None)
        }
        Err(e) => Err(e.context("loading the ML classifier (fix ml.* or set fail_mode: open to start without it)")),
    }
}

/// Resolve the `ml.*` paths against the config directory and load the model.
/// The tokenizer defaults to `tokenizer.json` next to the model.
fn load_classifier(ml: &MlConfig, base: &Path) -> anyhow::Result<nandi_ml::PromptInjectionClassifier> {
    let model = nandi_gateway::app::resolve(base, ml.model.as_deref().context("ml.model is not set")?);
    let tokenizer = match &ml.tokenizer {
        Some(t) => nandi_gateway::app::resolve(base, t),
        None => model.with_file_name("tokenizer.json"),
    };
    let runtime = ml.onnxruntime.as_deref().map(|p| nandi_gateway::app::resolve(base, p));
    nandi_ml::PromptInjectionClassifier::load(&model, &tokenizer, runtime.as_deref(), ml.max_tokens)
}

async fn wait_for(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

async fn run(config: &Path, log_level: &str) -> anyhow::Result<()> {
    let (cfg, base) = load_config(config)?;
    init_logging(log_level, cfg.telemetry.log_format.eq_ignore_ascii_case("json"));
    let classifier = ml_classifier(&cfg, &base)?;
    let app = App::build(cfg, &base, classifier)?;
    tracing::info!(mode = ?app.cfg.mode, proxy = %app.cfg.listen.proxy, "nandi {} starting", env!("CARGO_PKG_VERSION"));

    let (tx, rx) = watch::channel(false);
    let stop = tx.clone();
    tokio::spawn(async move {
        termination().await;
        tracing::info!("shutting down");
        let _ = stop.send(true);
    });
    if app.cfg.sensor.enabled {
        start_sensor(app.clone(), wait_for(rx.clone()));
    }
    let mut proxy_task = tokio::spawn(proxy::serve(app.clone(), wait_for(rx.clone())));
    let mut admin_task = if app.cfg.admin.listen.trim().is_empty() {
        let rx = rx.clone();
        tokio::spawn(async move {
            wait_for(rx).await;
            Ok::<(), anyhow::Error>(())
        })
    } else {
        tokio::spawn(admin::serve(app.clone(), wait_for(rx.clone())))
    };
    // When either listener ends (shutdown or error), stop the other one.
    let (first, other, first_name) = tokio::select! {
        r = &mut proxy_task => (r, admin_task, "proxy"),
        r = &mut admin_task => (r, proxy_task, "admin"),
    };
    let _ = tx.send(true);
    let second = tokio::time::timeout(Duration::from_secs(10), other).await;
    app.recorder.flush().await;
    app.shutdown();
    first.context("listener task panicked")?.with_context(|| format!("{first_name} listener"))?;
    if let Ok(r) = second {
        r.context("listener task panicked")??;
    }
    Ok(())
}

/// Run the host sensor inside the gateway so its events are correlated with
/// the tool calls the gateway sees.
fn start_sensor(app: Arc<App>, shutdown: impl std::future::Future<Output = ()> + Send + 'static) {
    #[cfg(target_os = "linux")]
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        let cfg = app.cfg.sensor.clone();
        tokio::spawn(async move {
            if let Err(e) = nandi_sense::run(cfg, tx, shutdown).await {
                tracing::error!(error = %e, "host sensor stopped");
            }
        });
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                app.decide(ev, &[]).await;
            }
        });
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (app, shutdown);
        tracing::warn!("sensor.enabled is set but the host sensor is only available on Linux");
    }
}

async fn sense_print(cfg: nandi_core::config::SensorConfig) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        let task = tokio::spawn(nandi_sense::run(cfg, tx, termination()));
        while let Some(ev) = rx.recv().await {
            println!("{}", serde_json::to_string(&ev)?);
        }
        task.await??;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        bail!("the host sensor is only available on Linux")
    }
}

fn sanitize(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

async fn wrap(config: &Path, opts: WrapOptions) -> anyhow::Result<i32> {
    let (mut cfg, base) = load_config(config)?;
    // redb allows one process per database file and several wrappers run at
    // once, so each wrapped server gets its own audit and state database.
    if cfg.audit.path.is_none() {
        cfg.audit.path = Some(cfg.data_dir().join(format!("wrap-{}.redb", sanitize(&opts.server))));
    }
    let classifier = ml_classifier(&cfg, &base)?;
    let app = App::build(cfg, &base, classifier)?;
    let code = stdio::run(app.clone(), opts).await;
    app.recorder.flush().await;
    app.shutdown();
    code
}

fn read_key_arg(key: &str) -> anyhow::Result<String> {
    if key == "-" {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        Ok(s.trim().to_string())
    } else {
        Ok(key.to_string())
    }
}

/// Output piped into `head` and closed early is not an error.
fn broken_pipe(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe))
}

fn exit_with(code: i32) -> ! {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    std::process::exit(code)
}

fn main() {
    let cli = Cli::parse();
    // Run everything on threads with explicit stacks. Static musl builds
    // report a small main-thread stack, which makes Cedar's stack guard
    // refuse to evaluate policies.
    let workers = std::env::var("NANDI_WORKER_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).min(4));
    let main = std::thread::Builder::new().name("nandi-main".into()).stack_size(8 << 20).spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .thread_stack_size(2 << 20)
            .enable_all()
            .build()
            .map_err(|e| anyhow::anyhow!("starting runtime: {e}"))?;
        rt.block_on(dispatch(cli))
    });
    let result = match main {
        Ok(handle) => handle.join().unwrap_or_else(|_| Err(anyhow::anyhow!("main thread panicked"))),
        Err(e) => Err(anyhow::anyhow!("spawning main thread: {e}")),
    };
    match result {
        Ok(code) => exit_with(code),
        Err(e) if broken_pipe(&e) => exit_with(0),
        Err(e) => {
            eprintln!("error: {e:#}");
            exit_with(1);
        }
    }
}

async fn dispatch(cli: Cli) -> anyhow::Result<i32> {
    let config = cli.config.as_path();
    if !matches!(cli.cmd, Cmd::Run) {
        // `run` picks its log format from the config.
        let level =
            if matches!(cli.cmd, Cmd::Hook { .. }) && cli.log_level == "info" { "warn" } else { &cli.log_level };
        init_logging(level, false);
    }
    match cli.cmd {
        Cmd::Run => run(config, &cli.log_level).await.map(|_| 0),
        Cmd::Wrap { server, agent, session, command } => {
            wrap(config, WrapOptions { server, agent, session, command }).await
        }
        Cmd::Hook { format, admin, token, fail_open } => {
            let format: HookFormat = format.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let opts = AdminOpts { admin, token, json: false };
            let (url, token) = remote::resolve_target(&opts, config);
            Ok(hook::client_main(format, &url, token.as_deref(), fail_open).await)
        }
        Cmd::Policy { cmd: PolicyCmd::Packs } => {
            for p in packs::PACKS {
                println!("{:<20} {}", p.name, p.summary());
            }
            println!("\nSave one with `nandi policy pack <name> > policies/<name>.yaml` and add it to policy.rules.");
            Ok(0)
        }
        Cmd::Policy { cmd: PolicyCmd::Pack { name } } => match packs::find(&name) {
            Some(p) => {
                print!("{}", p.yaml);
                Ok(0)
            }
            None => bail!("no pack named {name}; see `nandi policy packs`"),
        },
        Cmd::Policy { cmd } => {
            let (cfg, base) = load_config(config)?;
            match cmd {
                PolicyCmd::Validate => offline::validate(&cfg, &base)?,
                PolicyCmd::Test { events, json } => offline::test(&cfg, &base, &events, json)?,
                PolicyCmd::Packs | PolicyCmd::Pack { .. } => unreachable!("handled above"),
            }
            Ok(0)
        }
        Cmd::Replay { db, key, since_seq, limit, json } => {
            let (cfg, base) = load_config(config)?;
            let (db, key) = offline::audit_paths(&cfg, &base, db, key);
            let log = offline::open_audit(&db, &key)?;
            offline::replay(&cfg, &base, &log, since_seq, limit, json)?;
            Ok(0)
        }
        Cmd::Audit { cmd } => {
            let open = |db: Option<PathBuf>, key: Option<PathBuf>| -> anyhow::Result<_> {
                let (db, key) = match (db, key) {
                    (Some(db), Some(key)) => (db, key),
                    (db, key) => {
                        let (cfg, base) = load_config(config)?;
                        offline::audit_paths(&cfg, &base, db, key)
                    }
                };
                offline::open_audit(&db, &key)
            };
            match cmd {
                AuditCmd::Verify { export: Some(file), pubkey, .. } => {
                    offline::verify_export(&file, pubkey.as_deref().context("--pubkey is required")?)?
                }
                AuditCmd::Verify { db, key, .. } => offline::verify_db(&open(db, key)?)?,
                AuditCmd::Export { out, db, key } => offline::export(&open(db, key)?, &out)?,
                AuditCmd::Head { db, key } => offline::head(&open(db, key)?)?,
            }
            Ok(0)
        }
        Cmd::Key { cmd } => {
            match cmd {
                KeyCmd::Generate => {
                    let key = nandi_identity::generate_api_key();
                    println!("key:    {key}");
                    println!("sha256: {}", nandi_identity::hash_key(&key));
                    eprintln!("\nGive the key to the agent (header x-nandi-key); put only the sha256 in nandi.yaml:");
                    eprintln!(
                        "  identity:\n    api_keys:\n      - agent: my-agent\n        sha256: \"{}\"",
                        nandi_identity::hash_key(&key)
                    );
                }
                KeyCmd::Hash { key } => println!("{}", nandi_identity::hash_key(&read_key_arg(&key)?)),
            }
            Ok(0)
        }
        Cmd::Token { cmd: TokenCmd::Revoke { id, admin } } => {
            remote::revoke_token(&remote_for(&admin, config)?, &id, admin.json).await?;
            Ok(0)
        }
        Cmd::Token { cmd: TokenCmd::Revoked { admin } } => {
            remote::revoked_tokens(&remote_for(&admin, config)?, admin.json).await?;
            Ok(0)
        }
        Cmd::Token { cmd } => {
            use nandi_identity::biscuit;
            match cmd {
                TokenCmd::Keygen => {
                    let (private, public) = biscuit::generate_root_keypair();
                    println!("private: {private}");
                    println!("public:  {public}");
                    eprintln!(
                        "\nKeep the private key secret. Configure identity.biscuit.root_public_key with the public key."
                    );
                }
                TokenCmd::Mint { private_key, agent, tools, ttl } => {
                    println!("{}", biscuit::mint(&private_key, &agent, &tools, ttl)?)
                }
                TokenCmd::Attenuate { token, public_key, tools, ttl } => {
                    println!("{}", biscuit::attenuate(&token, &public_key, &tools, ttl)?)
                }
                TokenCmd::Inspect { token } => println!("{}", biscuit::inspect(&token)?),
                TokenCmd::Revoke { .. } | TokenCmd::Revoked { .. } => unreachable!("handled above"),
            }
            Ok(0)
        }
        Cmd::Status { admin } => {
            remote::status(&remote_for(&admin, config)?, admin.json).await?;
            Ok(0)
        }
        Cmd::Sessions { admin } => {
            remote::sessions(&remote_for(&admin, config)?, admin.json).await?;
            Ok(0)
        }
        Cmd::Approvals { cmd, admin } => {
            remote::approvals(&remote_for(&admin, config)?, cmd, admin.json).await?;
            Ok(0)
        }
        Cmd::Kill { agent, admin } => {
            remote::kill(&remote_for(&admin, config)?, &agent).await?;
            Ok(0)
        }
        Cmd::Revive { agent, admin } => {
            remote::revive(&remote_for(&admin, config)?, &agent).await?;
            Ok(0)
        }
        Cmd::Pins { cmd, cards, admin } => {
            remote::pins(&remote_for(&admin, config)?, cmd, cards, admin.json).await?;
            Ok(0)
        }
        Cmd::Servers { admin } => {
            remote::servers(&remote_for(&admin, config)?, admin.json).await?;
            Ok(0)
        }
        Cmd::Tail { agent, min_verdict, admin } => {
            let r = remote_for(&admin, config)?;
            tokio::select! {
                res = remote::tail(&r, agent.as_deref(), min_verdict.as_deref(), admin.json) => res?,
                _ = termination() => {}
            }
            Ok(0)
        }
        Cmd::Discover { home, projects, json, suggest, nandi_config, proxy_urls, report, admin, token } => {
            let args = discover::Args { home, projects, json, suggest, nandi_config, proxy_urls, report, admin, token };
            discover::run(args, config).await
        }
        Cmd::Init { dir, force } => {
            init::run(&dir, force)?;
            Ok(0)
        }
        Cmd::Eval { dir, json, min_detection, max_false_positives } => {
            let scenarios = nandi_eval::load_dir(&dir)?;
            let report = nandi_eval::run(&scenarios, None);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", nandi_eval::render(&report));
            }
            let s = &report.summary;
            let ok = s.detection_rate >= min_detection && s.false_positive_rate <= max_false_positives;
            Ok(if ok { 0 } else { 1 })
        }
        Cmd::Sense => {
            let (cfg, _) = load_config(config)?;
            sense_print(cfg.sensor).await?;
            Ok(0)
        }
        Cmd::Version => {
            println!("nandi {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
    }
}

fn remote_for(opts: &AdminOpts, config: &Path) -> anyhow::Result<Remote> {
    let (url, token) = remote::resolve_target(opts, config);
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        bail!("--admin must be an http:// or https:// URL");
    }
    Ok(Remote::new(url, token))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ml_cfg(fail_mode: FailMode) -> Config {
        let mut cfg = Config { fail_mode, ..Config::default() };
        cfg.ml.enabled = true;
        cfg.ml.model = Some(PathBuf::from("does-not-exist/model.onnx"));
        cfg
    }

    #[test]
    fn ml_disabled_builds_no_classifier() {
        assert!(ml_classifier(&Config::default(), Path::new(".")).unwrap().is_none());
    }

    #[test]
    fn ml_load_failure_follows_fail_mode() {
        let base = Path::new(".");
        assert!(ml_classifier(&ml_cfg(FailMode::Open), base).unwrap().is_none());
        let closed = ml_classifier(&ml_cfg(FailMode::Closed), base);
        if nandi_ml::AVAILABLE {
            let err = format!("{:#}", closed.err().expect("closed fail mode must refuse to start"));
            assert!(err.contains("ML classifier"), "{err}");
        } else {
            // Without the feature the config is accepted with a warning.
            assert!(closed.unwrap().is_none());
        }
    }
}
