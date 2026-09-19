#[derive(Debug, Clone, PartialEq)]
pub enum AddrClass {
    /// `0.0.0.0` / `::` — listens on every interface, reachable from
    /// anywhere the machine's network is reachable from.
    Any,
    /// `127.0.0.1`/`127.x.x.x` / `::1` — this machine only.
    Loopback,
    /// Bound to one specific interface IP — not "every interface," but
    /// still reachable from whatever network segment that interface is
    /// actually on (a LAN IP is not the safety guarantee loopback is).
    Specific(String),
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string: {hex:?}"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex byte in {hex:?}: {e}"))
        })
        .collect()
}

/// Decodes `/proc/net/tcp`'s IPv4 address encoding: 8 hex chars, the 4
/// bytes written in **reverse** (little-endian) of network byte order —
/// `"0100007F"` is `127.0.0.1`, not `1.0.0.127`. Empirically confirmed
/// against this machine's own `/proc/net/tcp`, not assumed from
/// documentation.
pub fn classify_ipv4(hex: &str) -> Result<AddrClass, String> {
    let raw = hex_to_bytes(hex)?;
    if raw.len() != 4 {
        return Err(format!(
            "expected 4 bytes (8 hex chars) for an IPv4 address, got {}",
            raw.len()
        ));
    }
    let bytes = [raw[3], raw[2], raw[1], raw[0]];
    classify_bytes_v4(bytes)
}

fn classify_bytes_v4(b: [u8; 4]) -> Result<AddrClass, String> {
    if b == [0, 0, 0, 0] {
        return Ok(AddrClass::Any);
    }
    if b[0] == 127 {
        return Ok(AddrClass::Loopback);
    }
    Ok(AddrClass::Specific(format!(
        "{}.{}.{}.{}",
        b[0], b[1], b[2], b[3]
    )))
}

/// Decodes `/proc/net/tcp6`'s IPv6 address encoding: 32 hex chars as 4
/// **words** of 4 bytes each, with bytes reversed *within each word*
/// (word order itself is preserved) — empirically confirmed live against
/// this machine: a socket bound to `::1` produces
/// `00000000000000000000000001000000`, and `::` produces all zeros.
pub fn classify_ipv6(hex: &str) -> Result<AddrClass, String> {
    let raw = hex_to_bytes(hex)?;
    if raw.len() != 16 {
        return Err(format!(
            "expected 16 bytes (32 hex chars) for an IPv6 address, got {}",
            raw.len()
        ));
    }
    let mut bytes = [0u8; 16];
    for word in 0..4 {
        let base = word * 4;
        bytes[base] = raw[base + 3];
        bytes[base + 1] = raw[base + 2];
        bytes[base + 2] = raw[base + 1];
        bytes[base + 3] = raw[base];
    }

    if bytes == [0u8; 16] {
        return Ok(AddrClass::Any);
    }
    if bytes[..15] == [0u8; 15] && bytes[15] == 1 {
        return Ok(AddrClass::Loopback);
    }
    // Simplified display (no RFC 5952 zero-compression) — sufficient to
    // identify *that* this is a specific address, full canonical
    // formatting is display polish, not a correctness requirement here.
    let groups: Vec<String> = bytes
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect();
    Ok(AddrClass::Specific(groups.join(":")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_zero_is_any() {
        assert_eq!(classify_ipv4("00000000").unwrap(), AddrClass::Any);
    }

    #[test]
    fn ipv4_loopback_matches_the_real_whatport_style_fixture() {
        // "0100007F" -> 127.0.0.1, the same encoding confirmed elsewhere
        // in this workspace (whatport's own proctcp tests).
        assert_eq!(classify_ipv4("0100007F").unwrap(), AddrClass::Loopback);
    }

    #[test]
    fn ipv4_other_127_addresses_are_still_loopback() {
        // 127.0.0.5 -> le hex bytes reversed: 05 00 00 7F
        assert_eq!(classify_ipv4("0500007F").unwrap(), AddrClass::Loopback);
    }

    #[test]
    fn ipv4_specific_interface_address() {
        // 192.168.1.10 -> reversed le: 0A 01 A8 C0
        let result = classify_ipv4("0A01A8C0").unwrap();
        assert_eq!(result, AddrClass::Specific("192.168.1.10".to_string()));
    }

    #[test]
    fn ipv6_all_zero_is_any_confirmed_against_a_real_bind_to_double_colon() {
        // Exact raw value observed live: `python3` binding to `('::', PORT)`.
        assert_eq!(
            classify_ipv6("00000000000000000000000000000000").unwrap(),
            AddrClass::Any
        );
    }

    #[test]
    fn ipv6_loopback_confirmed_against_a_real_bind_to_colon_colon_one() {
        // Exact raw value observed live: `python3` binding to `('::1', PORT)`.
        assert_eq!(
            classify_ipv6("00000000000000000000000001000000").unwrap(),
            AddrClass::Loopback
        );
    }

    #[test]
    fn ipv6_specific_address_is_neither_any_nor_loopback() {
        let result = classify_ipv6("00000000000000000000000002000000").unwrap();
        assert!(!matches!(result, AddrClass::Any));
        assert!(!matches!(result, AddrClass::Loopback));
    }

    #[test]
    fn malformed_hex_is_a_clean_error_not_a_panic() {
        assert!(classify_ipv4("not-hex-!").is_err());
        assert!(classify_ipv4("00").is_err()); // wrong length
        assert!(classify_ipv6("00").is_err());
    }
}
