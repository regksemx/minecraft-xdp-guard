mod config;
mod deny;
mod doctor;
mod ebpf;
mod hosts;
mod logging;
mod metrics;
mod pong;
mod shutdown;
mod telemetry;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use log::{error, info};

use config::Config;
use shutdown::Shutdown;

const USAGE: &str = "\
Usage: xdp-loader [OPTIONS] <INTERFACE>
       xdp-loader deny <COMMAND>    Change the deny list of the running
                                    filter, see `xdp-loader deny --help`
       xdp-loader detach [-c <FILE>] <INTERFACE>
                                    Remove a filter whose loader is gone
       xdp-loader doctor [-c <FILE>]
                                    Check the machine, the config and the
                                    running filter, and say what to change

SIGTERM and SIGINT stop the loader and detach the filter. SIGUSR1 and SIGHUP
stop the loader but leave the filter attached: the next start replaces it
without a gap (restart with a new configuration or binary).

Arguments:
  <INTERFACE>  Network interface to attach to

Options:
  -c, --config <FILE>  Path to the TOML configuration file, created with
                       defaults if missing [default: config.toml]
      --reset-state    Forget verified connections and known IPs kept from
                       an earlier run before starting (bans stay)
      --check          Load the filter with this configuration into the
                       kernel to see whether it is accepted, attach nothing
      --license        Print license information
  -h, --help           Print help
  -V, --version        Print version";

#[derive(Debug)]
struct Args {
    /// Network interface to attach to, required unless --license is given.
    interface: Option<String>,
    /// Path to the TOML configuration file.
    config: String,
    /// Print license information instead of running.
    license: bool,
    /// Remove the pinned state maps before loading.
    reset_state: bool,
    /// Only check that the kernel accepts the program.
    check: bool,
}

/// Hand-rolled argument parsing (a CLI library would double the binary size
/// for a handful of options). Prints help/version/errors and exits where appropriate.
fn parse_args() -> Args {
    let mut args = Args {
        interface: None,
        config: "config.toml".into(),
        license: false,
        reset_state: false,
        check: false,
    };

    let mut argv = std::env::args().skip(1);
    let invalid = |message: String| -> ! {
        eprintln!("error: {message}\n\n{USAGE}");
        std::process::exit(2);
    };
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("xdp-loader {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--license" => args.license = true,
            "--reset-state" => args.reset_state = true,
            "--check" => args.check = true,
            "-c" | "--config" => match argv.next() {
                Some(value) => args.config = value,
                None => invalid(format!("missing value for '{arg} <FILE>'")),
            },
            _ => match arg.strip_prefix("--config=") {
                Some(value) => args.config = value.into(),
                None if arg.starts_with('-') => invalid(format!("unexpected option '{arg}'")),
                None if args.interface.is_none() => args.interface = Some(arg),
                None => invalid(format!("unexpected argument '{arg}'")),
            },
        }
    }

    if args.interface.is_none() && !args.license && !args.check {
        invalid("missing required argument <INTERFACE>".into());
    }
    args
}

fn main() {
    // `xdp-loader deny ...` talks to the maps of the loader that is already
    // running, it never loads anything itself
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().is_some_and(|arg| arg == "deny") {
        if let Err(e) = deny::run(&argv[1..]) {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    if argv.first().is_some_and(|arg| arg == "doctor") {
        match doctor::run(&argv[1..]) {
            Ok(true) => return,
            Ok(false) => std::process::exit(1),
            Err(e) => {
                eprintln!("error: {e:#}");
                std::process::exit(2);
            }
        }
    }
    if argv.first().is_some_and(|arg| arg == "detach") {
        if let Err(e) = detach(&argv[1..]) {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
        return;
    }

    let args = parse_args();

    if args.license {
        println!(include_str!("../LICENSE"));
        return;
    }

    // the log level lives in the config, so it must be loaded before logging
    // is up; until then errors can only go to stderr directly
    let config = match Config::load(Path::new(&args.config)) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("failed to load config '{}': {e:#}", args.config);
            std::process::exit(1);
        }
    };

    logging::init(&config.logging).expect("Failed to setup logger");
    info!(
        "Loading minecraft xdp filter v{} by Outfluencer...",
        env!("CARGO_PKG_VERSION")
    );
    info!("Loaded configuration: {config:?}");

    let shutdown = Arc::new(Shutdown::new());
    shutdown::trigger_on_termination_signal(shutdown.clone());

    let result = run(&args, &config, &shutdown);
    if let Err(e) = &result {
        error!("{e:#}");
    }

    shutdown.trigger();
    info!("Good bye!");

    // a failed run must be visible to service managers (systemd
    // Restart=on-failure) and scripts, not only in the log
    if result.is_err() {
        std::process::exit(1);
    }
}

/// Attaches the XDP filter and keeps it alive until shutdown is triggered.
fn run(args: &Args, config: &Config, shutdown: &Arc<Shutdown>) -> Result<()> {
    if args.check {
        ebpf::check(config)?;
        info!("The kernel accepted the filter with this configuration");
        return Ok(());
    }

    let interface = args
        .interface
        .as_deref()
        .context("interface is required unless --license or --check is specified")?;

    if args.reset_state {
        ebpf::remove_state(config, false);
    }

    let mut filter = ebpf::load_and_attach(interface, config)?;
    let result = serve(&mut filter, config, Path::new(&args.config), shutdown);

    if result.is_ok() && shutdown.hand_over() {
        // the pinned attachment and maps keep filtering on their own
        info!("Leaving the filter attached, the next start takes it over");
    } else {
        filter.detach();
        if !config.xdp.keep_state {
            ebpf::remove_state(config, true);
        }
    }
    result
}

/// Publishes metrics and refreshes the pong cache until shutdown is
/// triggered.
fn serve(
    filter: &mut ebpf::Filter,
    config: &Config,
    config_path: &Path,
    shutdown: &Arc<Shutdown>,
) -> Result<()> {
    let stats_thread = metrics::start(&mut filter.ebpf, config, shutdown)?;
    let pong_thread = pong::start(&mut filter.ebpf, config, shutdown)?;
    let telemetry_thread = telemetry::start(config, config_path, filter.mode, shutdown)?;

    shutdown.wait();

    for (name, handle) in [
        ("track-stats", stats_thread),
        ("pong-refresh", pong_thread),
        ("telemetry", telemetry_thread),
    ] {
        if let Some(handle) = handle {
            handle
                .join()
                .map_err(|e| anyhow::anyhow!("{name} thread panicked: {e:?}"))?;
        }
    }
    Ok(())
}

/// `xdp-loader detach [-c <FILE>] <INTERFACE>`
fn detach(args: &[String]) -> Result<()> {
    let mut config_path = None;
    let mut interface = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                config_path = Some(args.next().context("missing value for --config")?.as_str());
            }
            _ if interface.is_none() => interface = Some(arg.as_str()),
            _ => anyhow::bail!("unexpected argument '{arg}'"),
        }
    }
    let interface = interface.context("missing <INTERFACE>")?;
    let config = deny::load_config(config_path)?;
    if ebpf::detach_interface(&config, interface)? {
        println!("detached the filter from {interface}");
    } else {
        println!("no filter of a stopped loader is attached to {interface}");
    }
    Ok(())
}
