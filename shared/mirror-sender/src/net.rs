//! Socket helpers: LAN-only peer policy, listener binding, stream options.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use socket2::{Domain, Protocol, SockRef, Socket, Type};

/// LAN-only peer policy (PLAN §6).
///
/// Allowed: site-local IPv4 (10/8, 172.16/12, 192.168/16), IPv6 link-local
/// (fe80::/10) and unique-local (fc00::/7), and — when `allow_loopback` —
/// 127.0.0.0/8 and ::1. IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, as seen
/// on a dual-stack listener) are judged as their IPv4 address. Everything
/// else (public, CGNAT 100.64/10, IPv4 link-local, multicast, unspecified)
/// is rejected.
pub fn is_allowed_peer(ip: IpAddr, allow_loopback: bool) -> bool {
    match ip {
        IpAddr::V4(a) => v4_allowed(a, allow_loopback),
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => v4_allowed(v4, allow_loopback),
            None => v6_allowed(a, allow_loopback),
        },
    }
}

fn v4_allowed(a: Ipv4Addr, allow_loopback: bool) -> bool {
    a.is_private() || (allow_loopback && a.is_loopback())
}

fn v6_allowed(a: Ipv6Addr, allow_loopback: bool) -> bool {
    let s0 = a.segments()[0];
    let link_local = s0 & 0xffc0 == 0xfe80;
    let unique_local = s0 & 0xfe00 == 0xfc00;
    link_local || unique_local || (allow_loopback && a.is_loopback())
}

/// Bind the listening socket. `port == 0` asks for an ephemeral port; a busy
/// non-zero port falls back to an ephemeral one. `bind_addr == None` binds
/// dual-stack `[::]`, falling back to `0.0.0.0` if IPv6 is unavailable.
pub(crate) fn bind_listener(bind_addr: Option<IpAddr>, port: u16) -> io::Result<TcpListener> {
    let try_bind = |port: u16| -> io::Result<TcpListener> {
        match bind_addr {
            Some(ip) => bind_one(SocketAddr::new(ip, port), false),
            None => {
                match bind_one(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port), true) {
                    // A busy port is not a missing IPv6 stack: keep dual-stack
                    // (and let the caller pick another port) rather than
                    // silently serving IPv4 only.
                    Err(e) if e.kind() == io::ErrorKind::AddrInUse => Err(e),
                    Err(e) => {
                        log::debug!("dual-stack bind failed ({e}); using IPv4 only");
                        bind_one(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port), false)
                    }
                    ok => ok,
                }
            }
        }
    };
    match try_bind(port) {
        Err(e) if port != 0 && e.kind() == io::ErrorKind::AddrInUse => {
            log::info!("port {port} busy; falling back to an ephemeral port");
            try_bind(0)
        }
        r => r,
    }
}

fn bind_one(addr: SocketAddr, dual_stack: bool) -> io::Result<TcpListener> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if dual_stack {
        sock.set_only_v6(false)?;
    }
    // Lets a restarted server rebind while old connections sit in TIME_WAIT.
    sock.set_reuse_address(true)?;
    sock.bind(&addr.into())?;
    sock.listen(16)?;
    Ok(sock.into())
}

/// Make `accept` on `l` blocking with `timeout` (SO_RCVTIMEO), so the
/// accept thread sleeps in the kernel instead of polling. Linux/Android
/// only: there SO_RCVTIMEO bounds `accept` (EAGAIN), so a lost wake-up
/// cannot hang `stop()`; macOS ignores it for `accept`. False where not
/// supported or not set (the caller then polls a non-blocking socket).
pub(crate) fn set_accept_timeout(l: &TcpListener, timeout: Duration) -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
        && l.set_nonblocking(false).is_ok()
        && SockRef::from(l).set_read_timeout(Some(timeout)).is_ok()
}

/// Wake a thread blocked in `accept` on the listener bound to `local`, by
/// connecting to it (best effort). An unspecified bind address is reached
/// through loopback.
pub(crate) fn wake_listener(local: SocketAddr) {
    let port = local.port();
    let targets: Vec<SocketAddr> = match local.ip() {
        IpAddr::V6(a) if a.is_unspecified() => vec![
            (Ipv6Addr::LOCALHOST, port).into(),
            (Ipv4Addr::LOCALHOST, port).into(),
        ],
        IpAddr::V4(a) if a.is_unspecified() => vec![(Ipv4Addr::LOCALHOST, port).into()],
        _ => vec![local],
    };
    for t in targets {
        if TcpStream::connect_timeout(&t, Duration::from_millis(200)).is_ok() {
            return;
        }
    }
    log::debug!("could not wake the accept thread on {local}; it stops within its timeout");
}

/// Per-connection socket options.
pub(crate) fn configure_stream(s: &TcpStream, send_buffer: usize) {
    // Accepted sockets inherit O_NONBLOCK from the listener on BSD/macOS.
    if let Err(e) = s.set_nonblocking(false) {
        log::warn!("set_nonblocking(false) failed: {e}");
    }
    let sock = SockRef::from(s);
    if let Err(e) = sock.set_tcp_nodelay(true) {
        log::warn!("TCP_NODELAY failed: {e}");
    }
    if send_buffer > 0 {
        if let Err(e) = sock.set_send_buffer_size(send_buffer) {
            log::warn!("SO_SNDBUF={send_buffer} failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str, lo: bool) -> bool {
        is_allowed_peer(s.parse().unwrap(), lo)
    }

    #[test]
    fn lan_ipv4() {
        for a in ["10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.20"] {
            assert!(ok(a, false), "{a}");
        }
        for a in [
            "8.8.8.8",
            "172.32.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",
        ] {
            assert!(!ok(a, false), "{a}");
        }
    }

    #[test]
    fn loopback_gated() {
        assert!(ok("127.0.0.1", true));
        assert!(ok("127.1.2.3", true));
        assert!(ok("::1", true));
        assert!(!ok("::1", false));
        assert!(ok("::ffff:127.0.0.1", true));
        assert!(!ok("::ffff:127.0.0.1", false));
    }

    /// A port busy for IPv6 only must not yield an IPv4-only listener on
    /// it: the dual-stack listener moves to another port instead.
    #[test]
    fn port_busy_on_ipv6_keeps_dual_stack() {
        let Ok(v6) = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) else {
            return;
        };
        v6.set_only_v6(true).unwrap();
        if v6
            .bind(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0).into())
            .is_err()
        {
            return; // no IPv6 here
        }
        v6.listen(1).unwrap();
        let port = v6.local_addr().unwrap().as_socket().unwrap().port();
        let l = bind_listener(None, port).unwrap();
        let got = l.local_addr().unwrap();
        assert!(got.is_ipv6(), "{got}");
        assert_ne!(got.port(), port);
    }

    #[test]
    fn lan_ipv6() {
        for a in [
            "fe80::1",
            "febf::1",
            "fd12:3456::1",
            "fc00::1",
            "::ffff:192.168.0.2",
        ] {
            assert!(ok(a, false), "{a}");
        }
        for a in [
            "2001:db8::1",
            "2a00:1450::1",
            "fec0::1",
            "ff02::fb",
            "::",
            "::ffff:8.8.8.8",
        ] {
            assert!(!ok(a, false), "{a}");
        }
    }
}
