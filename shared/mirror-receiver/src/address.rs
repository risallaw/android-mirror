//! "Connect by IP" input parsing: `host`, `host:port`, `[v6]:port` or a
//! bare IPv6 address; the port defaults to [`DEFAULT_PORT`]. IPv6 addresses
//! may carry a zone (`fe80::1%en0`, needed for link-local addresses), and a
//! name may end in a dot (`phone.lan.`).

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};

/// The sender's default listening port (PLAN.md §2).
pub const DEFAULT_PORT: u16 = 47800;

/// A parsed, not yet resolved, connect target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Why an address could not be parsed. `Display` is user-facing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    BadPort(String),
    BadHost(String),
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::Empty => write!(f, "Enter the phone's IP address."),
            AddressError::BadPort(p) => {
                write!(f, "\"{p}\" is not a valid port (use 1–65535).")
            }
            AddressError::BadHost(h) => write!(f, "\"{h}\" is not a valid address."),
        }
    }
}

impl std::error::Error for AddressError {}

fn parse_port(p: &str) -> Result<u16, AddressError> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(AddressError::BadPort(p.to_string())),
        Ok(n) => Ok(n),
    }
}

/// An IPv6 literal, optionally with a `%zone` (interface name or index).
fn valid_ipv6(h: &str) -> bool {
    let (addr, zone) = match h.split_once('%') {
        Some((a, z)) => (a, Some(z)),
        None => (h, None),
    };
    addr.parse::<Ipv6Addr>().is_ok()
        && zone.is_none_or(|z| {
            !z.is_empty()
                && z.len() <= 64
                && z.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

fn valid_hostname(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        // A numeric last label is never a name: it is a mistyped IPv4
        // address (`192.168.1.420`), caught here instead of after a DNS wait.
        && !h.rsplit('.').next().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
        && h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Parse user input into a [`Target`]. Pure; no DNS.
pub fn parse_target(input: &str) -> Result<Target, AddressError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(AddressError::Empty);
    }
    // [v6] or [v6]:port
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| AddressError::BadHost(s.to_string()))?;
        if !valid_ipv6(host) {
            return Err(AddressError::BadHost(host.to_string()));
        }
        let port = match after {
            "" => DEFAULT_PORT,
            p => parse_port(
                p.strip_prefix(':')
                    .ok_or_else(|| AddressError::BadHost(s.to_string()))?,
            )?,
        };
        return Ok(Target {
            host: host.to_string(),
            port,
        });
    }
    // A bare IPv6 address has several colons.
    if s.matches(':').count() > 1 {
        return if valid_ipv6(s) {
            Ok(Target {
                host: s.to_string(),
                port: DEFAULT_PORT,
            })
        } else {
            Err(AddressError::BadHost(s.to_string()))
        };
    }
    let (host, port) = match s.split_once(':') {
        Some((h, p)) => (h, parse_port(p)?),
        None => (s, DEFAULT_PORT),
    };
    // A trailing dot marks a fully qualified name; on an IPv4 address it is
    // just dropped.
    let bare = host.strip_suffix('.').unwrap_or(host);
    let host = if bare.parse::<IpAddr>().is_ok() {
        bare
    } else if valid_hostname(bare) {
        host
    } else {
        // Show the whole input when the host part is empty (`:80`).
        let shown = if host.is_empty() { s } else { host };
        return Err(AddressError::BadHost(shown.to_string()));
    };
    Ok(Target {
        host: host.to_string(),
        port,
    })
}

/// Resolve a target (blocking: may hit DNS/mDNS for names; a zoned IPv6
/// literal goes through the system resolver, which maps the zone to the
/// scope id). Prefers IPv4, which is what the phone listens on.
pub fn resolve(target: &Target) -> std::io::Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = (target.host.as_str(), target.port)
        .to_socket_addrs()?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no address found for {}", target.host),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(host: &str, port: u16) -> Target {
        Target {
            host: host.into(),
            port,
        }
    }

    #[test]
    fn ipv4_with_and_without_port() {
        assert_eq!(
            parse_target("192.168.1.42"),
            Ok(t("192.168.1.42", DEFAULT_PORT))
        );
        assert_eq!(parse_target("  10.0.0.7:5000 "), Ok(t("10.0.0.7", 5000)));
    }

    #[test]
    fn hostnames() {
        assert_eq!(
            parse_target("pixel-8.local"),
            Ok(t("pixel-8.local", DEFAULT_PORT))
        );
        assert_eq!(parse_target("localhost:1"), Ok(t("localhost", 1)));
        assert!(matches!(
            parse_target("bad host"),
            Err(AddressError::BadHost(_))
        ));
        assert!(matches!(
            parse_target("-x.lan"),
            Err(AddressError::BadHost(_))
        ));
        assert!(matches!(
            parse_target("a..b"),
            Err(AddressError::BadHost(_))
        ));
        assert_eq!(
            parse_target(":80"),
            Err(AddressError::BadHost(":80".into()))
        );
    }

    #[test]
    fn mistyped_ipv4_is_rejected_not_resolved() {
        for s in ["192.168.1.420", "10.0.0.256:5000", "1.2.3"] {
            assert!(
                matches!(parse_target(s), Err(AddressError::BadHost(_))),
                "{s}"
            );
        }
        assert!(parse_target("host1.local").is_ok());
        assert!(parse_target("a.b2").is_ok());
    }

    #[test]
    fn ipv6_forms() {
        assert_eq!(parse_target("fe80::1"), Ok(t("fe80::1", DEFAULT_PORT)));
        assert_eq!(parse_target("[fd00::2]:4000"), Ok(t("fd00::2", 4000)));
        assert_eq!(parse_target("[fd00::2]"), Ok(t("fd00::2", DEFAULT_PORT)));
        assert!(parse_target("[fd00::2]4000").is_err());
        assert!(parse_target("[nope]:1").is_err());
        assert!(parse_target("fe80::zz").is_err());
        assert_eq!(t("fd00::2", 4000).to_string(), "[fd00::2]:4000");
    }

    #[test]
    fn zoned_ipv6() {
        assert_eq!(
            parse_target("fe80::1%en0"),
            Ok(t("fe80::1%en0", DEFAULT_PORT))
        );
        assert_eq!(
            parse_target("[fe80::1%en0]:4000"),
            Ok(t("fe80::1%en0", 4000))
        );
        assert_eq!(
            parse_target("[fe80::1%7]"),
            Ok(t("fe80::1%7", DEFAULT_PORT))
        );
        assert_eq!(t("fe80::1%en0", 4000).to_string(), "[fe80::1%en0]:4000");
        for bad in [
            "fe80::1%",
            "[fe80::1%]:1",
            "fe80::1%a b",
            "fe80::zz%en0",
            "1.2.3.4%en0",
        ] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn zoned_ipv6_resolves_with_its_scope() {
        // Numeric zones work on every OS; names need the interface to exist.
        let a = resolve(&t("fe80::1%1", 9)).unwrap();
        match a {
            SocketAddr::V6(v6) => {
                assert_eq!(*v6.ip(), "fe80::1".parse::<Ipv6Addr>().unwrap());
                assert_eq!(v6.scope_id(), 1);
                assert_eq!(v6.port(), 9);
            }
            other => panic!("{other}"),
        }
    }

    #[test]
    fn trailing_dot() {
        assert_eq!(
            parse_target("phone.lan."),
            Ok(t("phone.lan.", DEFAULT_PORT))
        );
        assert_eq!(parse_target("phone.lan.:5000"), Ok(t("phone.lan.", 5000)));
        assert_eq!(
            parse_target("192.168.1.4."),
            Ok(t("192.168.1.4", DEFAULT_PORT))
        );
        assert_eq!(parse_target("192.168.1.4.:9"), Ok(t("192.168.1.4", 9)));
        for bad in [".", "a..", "phone.lan..", "1.2.3."] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn bad_ports_and_empty() {
        assert_eq!(parse_target("   "), Err(AddressError::Empty));
        assert_eq!(
            parse_target("1.2.3.4:0"),
            Err(AddressError::BadPort("0".into()))
        );
        assert_eq!(
            parse_target("1.2.3.4:70000"),
            Err(AddressError::BadPort("70000".into()))
        );
        assert_eq!(
            parse_target("1.2.3.4:"),
            Err(AddressError::BadPort("".into()))
        );
        assert!(AddressError::Empty.to_string().contains("IP address"));
    }

    #[test]
    fn display_round_trips() {
        for s in ["192.168.1.42:47800", "phone.lan:1234", "[::1]:9"] {
            assert_eq!(parse_target(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn resolves_literal_ip_without_dns() {
        let a = resolve(&t("127.0.0.1", 47800)).unwrap();
        assert_eq!(a, "127.0.0.1:47800".parse().unwrap());
    }
}
