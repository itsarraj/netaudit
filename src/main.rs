use std::io::{self, ErrorKind, Write};
use std::path::Path;

use clap::Parser;
use netaudit::{scan, scan_all, Finding};

#[derive(Parser)]
#[command(
    name = "netaudit",
    about = "Which of your listening ports are reachable from the network, not just localhost"
)]
struct Cli {
    /// Also list loopback-bound (safe) sockets, not just exposed ones.
    #[arg(long)]
    all: bool,
    #[arg(long)]
    json: bool,
}

/// Ignores a broken pipe rather than propagating it — found live by
/// piping real output into `head`: the default `println!` panics the
/// moment the reader goes away, which is a real bug for a tool whose
/// output people will obviously want to pipe into `head`/`less`/`grep`.
/// Any other write error still surfaces normally.
fn ignore_broken_pipe(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == ErrorKind::BrokenPipe => Ok(()),
        other => other,
    }
}

fn print_text(out: &mut impl Write, findings: &[Finding]) -> io::Result<()> {
    for f in findings {
        let risk_note = f
            .risky_service
            .map(|s| format!("  [{s}]"))
            .unwrap_or_default();
        let scope = if f.exposed { "EXPOSED" } else { "local  " };
        let proc = match (&f.pid, &f.process_name) {
            (Some(pid), Some(name)) => format!("pid {pid} ({name})"),
            (Some(pid), None) => format!("pid {pid}"),
            (None, _) => "unknown process".to_string(),
        };
        writeln!(
            out,
            "{scope}  {:<20} port {:<6} {proc}{risk_note}",
            f.bound_to, f.port
        )?;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let proc_root = Path::new("/proc");

    let findings = if cli.all {
        scan_all(proc_root)
    } else {
        scan(proc_root)
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    ignore_broken_pipe(if cli.json {
        writeln!(out, "{}", serde_json::to_string_pretty(&findings)?)
    } else if findings.is_empty() {
        writeln!(out, "nothing exposed beyond loopback")
    } else {
        print_text(&mut out, &findings)
    })?;

    let high_risk = findings
        .iter()
        .any(|f| f.exposed && f.risky_service.is_some());
    if high_risk {
        std::process::exit(1);
    }
    Ok(())
}
