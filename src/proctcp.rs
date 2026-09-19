use crate::addr::{classify_ipv4, classify_ipv6, AddrClass};

#[derive(Debug, Clone, PartialEq)]
pub struct ListeningSocket {
    pub port: u16,
    pub addr: AddrClass,
    pub inode: u64,
    pub ipv6: bool,
}

const TCP_LISTEN: u8 = 0x0A;

/// Parses `/proc/net/tcp` or `/proc/net/tcp6` (same column layout for
/// both, only the address field's hex length differs — 8 chars for IPv4,
/// 32 for IPv6) and returns every socket in the `LISTEN` state.
pub fn parse_listen_sockets(contents: &str, ipv6: bool) -> Vec<ListeningSocket> {
    let mut result = Vec::new();
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Ok(state) = u8::from_str_radix(fields[3], 16) else {
            continue;
        };
        if state != TCP_LISTEN {
            continue;
        }
        let Some((addr_hex, port_hex)) = fields[1].split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };

        let addr = if ipv6 {
            classify_ipv6(addr_hex)
        } else {
            classify_ipv4(addr_hex)
        };
        let Ok(addr) = addr else { continue };

        result.push(ListeningSocket {
            port,
            addr,
            inode,
            ipv6,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1538 0A00A8C0:C6C4 01 00000000:00000000 00:00000000 00000000     0        0 333 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_listen_sockets_with_correct_address_classification() {
        let sockets = parse_listen_sockets(FIXTURE_TCP, false);
        // Only the two LISTEN (state 0A) rows, the ESTABLISHED (01) one excluded.
        assert_eq!(sockets.len(), 2);

        let exposed = sockets.iter().find(|s| s.port == 8080).unwrap(); // 0x1F90
        assert_eq!(exposed.addr, AddrClass::Any);
        assert_eq!(exposed.inode, 111);

        let local = sockets.iter().find(|s| s.port == 80).unwrap(); // 0x0050
        assert_eq!(local.addr, AddrClass::Loopback);
        assert_eq!(local.inode, 222);
    }

    #[test]
    fn non_listen_state_is_excluded() {
        let sockets = parse_listen_sockets(FIXTURE_TCP, false);
        assert!(!sockets.iter().any(|s| s.port == 0x1538));
    }

    #[test]
    fn empty_table_returns_empty() {
        assert_eq!(parse_listen_sockets("header only\n", false), vec![]);
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let contents = "header\nnot enough fields\n";
        assert_eq!(parse_listen_sockets(contents, false), vec![]);
    }

    #[test]
    fn ipv6_flag_selects_the_ipv6_decoder() {
        let contents = "header\n   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 444 1 0 100 0 0 10 0\n";
        let sockets = parse_listen_sockets(contents, true);
        assert_eq!(sockets.len(), 1);
        assert!(sockets[0].ipv6);
        assert_eq!(sockets[0].addr, AddrClass::Any);
    }
}
