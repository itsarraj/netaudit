pub mod addr;
pub mod procinfo;
pub mod proctcp;
pub mod risk;

use std::path::Path;

use serde::Serialize;

use addr::AddrClass;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub port: u16,
    pub ipv6: bool,
    pub bound_to: String,
    pub exposed: bool,
    pub risky_service: Option<&'static str>,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

/// The full pipeline: read `net/tcp` + `net/tcp6` under `proc_root`,
/// classify every listening socket's bound address, resolve to a PID
/// where possible, and cross-reference the port against known-risky
/// service ports. Returns every non-loopback finding — `Any` (exposed to
/// everything) and `Specific` (exposed to one interface's network) alike
/// — sorted with risky-service findings first. Loopback-bound sockets are
/// the safe case and aren't included here; `main.rs`'s `--all` flag is
/// what surfaces those too, for a complete-picture view.
pub fn scan(proc_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (rel, ipv6) in [("net/tcp", false), ("net/tcp6", true)] {
        let Ok(contents) = std::fs::read_to_string(proc_root.join(rel)) else {
            continue;
        };
        for socket in proctcp::parse_listen_sockets(&contents, ipv6) {
            if socket.addr == AddrClass::Loopback {
                continue;
            }
            findings.push(to_finding(proc_root, &socket));
        }
    }

    findings.sort_by(|a, b| {
        b.risky_service
            .is_some()
            .cmp(&a.risky_service.is_some())
            .then_with(|| a.port.cmp(&b.port))
    });
    findings
}

/// Same as `scan`, but includes loopback-bound sockets too (marked
/// `exposed: false`) — the `--all` view.
pub fn scan_all(proc_root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rel, ipv6) in [("net/tcp", false), ("net/tcp6", true)] {
        let Ok(contents) = std::fs::read_to_string(proc_root.join(rel)) else {
            continue;
        };
        for socket in proctcp::parse_listen_sockets(&contents, ipv6) {
            findings.push(to_finding(proc_root, &socket));
        }
    }
    findings.sort_by_key(|f| f.port);
    findings
}

fn to_finding(proc_root: &Path, socket: &proctcp::ListeningSocket) -> Finding {
    let pid = procinfo::find_pid_for_inode(proc_root, socket.inode);
    let process_name = pid.and_then(|p| procinfo::process_name(proc_root, p));
    let (bound_to, exposed) = match &socket.addr {
        AddrClass::Any => (
            if socket.ipv6 {
                "::".to_string()
            } else {
                "0.0.0.0".to_string()
            },
            true,
        ),
        AddrClass::Specific(ip) => (ip.clone(), true),
        AddrClass::Loopback => (
            if socket.ipv6 {
                "::1".to_string()
            } else {
                "127.0.0.1".to_string()
            },
            false,
        ),
    };
    Finding {
        port: socket.port,
        ipv6: socket.ipv6,
        bound_to,
        exposed,
        risky_service: risk::risky_service_name(socket.port),
        pid,
        process_name,
    }
}
